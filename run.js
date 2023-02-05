#!/usr/bin/env node

const progress = require('cli-progress')
const chalk = require('chalk')

const fs = require('fs').promises
const fsr = require('fs')
const path = require('path')
const os = require('os')
const shell = require('shelljs')
const fetch = require('node-fetch')
const crypto = require('crypto')
const fse = require('fs-extra')
const dataConfig = require('./config.json')

const mkdirp = require('./lib/mkdirp')
const zip = require('./lib/zip')

const BAR_OPTS = {
    format: chalk.cyan('{bar}') +
        chalk.grey(' | {percentage}% | {received}/{size}'),
    barCompleteChar: '\u2588',
    barIncompleteChar: '\u2591',
}

function toBarPayload(obj) {
    const result = {}
    for (let key of ['received', 'size']) {
        result[key] = (obj[key] / 1024 / 1024).toFixed(2) + 'Mib'
    }
    return result
}

class Blob {
    session = ''
    index = 0
    size = 0
    received = 0
    storage = []

    constructor(session, size) {
        this.session = session
        this.size = size

        this.bar = new progress.SingleBar(BAR_OPTS)
        this.bar.start(size, 0)
    }

    feed(index, data) {
        if (index != this.index + 1)
            throw new Error(`invalid index ${index}, expected ${blob.index + 1}`)

        this.received += data.length
        this.storage.push(data)
        this.index++
        this.bar.update(this.received, toBarPayload(this))
    }

    done() {
        this.bar.stop()
        return Buffer.concat(this.storage)
    }
}

class File {
    session = ''
    index = 0
    size = 0
    received = 0
    name = ''
    fd = null
    bar = null
    verbose = false

    constructor(session, size, fd) {
        this.session = session
        this.size = size
        this.fd = fd

        if (size > 4 * 1024 * 1024) {
            this.bar = new progress.SingleBar(BAR_OPTS)
            this.bar.start(size, 0)
            this.verbose = true
        }

    }

    progress(length) {
        this.received += length
        if (this.verbose)
            this.bar.update(this.received, toBarPayload(this))
    }

    done() {
        if (this.verbose)
            this.bar.stop()
        this.fd.close()
    }
}

class Handler {
    /**
     * @param {string} cwd working directory
     * @param {string} root bundle root
     */
    constructor(cwd, root) {
        this.script = null
        this.blobs = new Map()
        this.files = new Map()
        this.root = root
        this.cwd = cwd
        this.session = null
        this.misc = {}
    }

    /**
     * get Blob by uuid
     * @param {string} id uuid
     */
    blob(id) {
        const blob = this.blobs.get(id)
        if (!blob) {
            // console.log('id', id, this.blobs)
            throw new Error('invalid session id')
        }
        return blob
    }

    /**
     * get file object by uuid
     * @param {string} id uuid
     */
    file(id) {
        const fd = this.files.get(id)
        if (!fd) {
            throw new Error('invalid file id')
        }
        return fd
    }

    async memcpy({event, session, size, index}, data) {
        if (event === 'begin') {
            console.log(chalk.green('fetching decrypted data'))

            const blob = new Blob(session, size)
            this.blobs.set(session, blob)
            this.ack()
        } else if (event === 'data') {
            const blob = this.blob(session)
            blob.feed(index, data)
            this.ack()
        } else if (event === 'end') {

        } else {
            throw new Error('NOTREACHED')
        }
    }

    /**
     * secure path concatenation
     * @param {string} filename relative path component
     */
    async output(filename) {
        const abs = path.resolve(this.cwd, path.relative(this.root, filename))
        const rel = path.relative(this.cwd, abs)
        if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) {
            await mkdirp(path.dirname(abs))
            return abs
        }
        throw Error(`Suspicious path detected: ${filename}`)
    }

    async patch({offset, blob, size, filename}) {
        const output = await this.output(filename)
        const fd = await fs.open(output, 'r+')
        let buf = null
        if (blob) {
            buf = this.blob(blob).done()
            this.blobs.delete(blob)
        } else if (size) {
            buf = Buffer.alloc(size)
            buf.fill(0)
        } else {
            throw new Error('NOTREACHED')
        }

        await fd.write(buf, 0, buf.length, offset)
        await fd.close()
    }

    ack() {
        this.script.post({type: 'ack'}, Buffer.allocUnsafe(1))
    }

    truncate(str) {
        const MAX = 80
        const len = str.length - MAX
        return len > 0 ? `...${str.substr(len)}` : str
    }

    async download({event, session, stat, filename}, data) {
        if (event === 'begin') {
            console.log(chalk.bold('download'), chalk.greenBright(this.truncate(filename)))
            const output = await this.output(filename)
            const fd = await fs.open(output, 'w', stat.mode)
            const file = new File(session, stat.size, fd)
            this.files.set(session, file)
            try {
                await fs.utimes(output, stat.atimeMs, stat.mtimeMs)
            } catch (e) {
                this.misc.warnAboutNTFS = e.code === 'EINVAL' && os.platform() === 'win32'
            }
            this.ack()
        } else if (event === 'data') {
            const file = this.file(session)
            file.progress(data.length)
            await file.fd.write(data)
            this.ack()
        } else if (event === 'end') {
            const file = this.file(session)
            file.done()
            this.files.delete(session)
        } else {
            throw new Error('NOTREACHED')
        }
    }

    connect(script) {
        this.script = script
        script.message.connect(this.dispatcher.bind(this))
    }

    dispatcher({type, payload}, data) {
        if (type === 'send') {
            const {subject} = payload;
            if (['memcpy', 'download', 'patch'].includes(subject)) {
                // don't wait
                // console.log(subject)
                this[subject].call(this, payload, data)
            }
        } else if (type === 'error') {
            this.session.detach()
        } else {
            console.log('UNKNOWN', type, payload, data)
        }
    }
}

function detached(reason, crash) {
    if (reason === 'application-requested')
        return

    console.error(chalk.red('FATAL ERROR: session detached'))
    console.error('reason:', chalk.yellow(reason))
    if (reason === 'server-terminated')
        return

    if (!crash)
        return

    for (let [key, val] of Object.entries(crash))
        console.log(`${key}:`, typeof val === 'string' ? chalk.redBright(val) : val)
}

function calculateHash(filePath) {
    return new Promise((resolve, reject) => {
        let hash = crypto.createHash('sha1')
        let rs = fsr.createReadStream(filePath)
        rs.on('open', () => {
        })
        rs.on('error', (err) => {
            reject(err)
        })
        rs.on('data', (chunk) => {
            hash.update(chunk)
        })
        rs.on('end', () => {
            resolve(hash.digest("hex"))
        })
    })
}

async function dump(dev, session, opt) {
    const {output} = opt
    await mkdirp(output)
    const parent = path.join(output, opt.app, 'Payload')

    try {
        const stat = await fs.stat(parent)
        if (stat.isDirectory() && !opt.override)
            throw new Error(`Destination ${parent} already exists. Try --override`)
    } catch (ex) {
        if (ex.code !== 'ENOENT')
            throw ex
    }

    session.detached.connect(detached)

    const read = (...args) => fs.readFile(path.join(__dirname, ...args)).then(buf => buf.toString())
    const js = await read('dist', 'agent.js')
    const c = await read('cmod', 'source.c')

    const script = await session.createScript(js)
    await script.load()
    const root = await script.exports.base()
    const cwd = path.join(parent, path.basename(root))
    await mkdirp(cwd)

    console.log('app root:', chalk.green(root))

    const handler = new Handler(cwd, root)
    handler.connect(script)

    console.log('dump main app')

    const sanitized = {
        executableOnly: opt.executableOnly
    }

    await script.exports.prepare(c)
    await script.exports.dump(sanitized)

    if (opt.extension) {
        console.log('patch PluginKit validation')
        const pkdSession = await dev.attach('pkd')
        const pkdScript = await pkdSession.createScript(js)
        await pkdScript.load()
        await pkdScript.exports.skipPkdValidationFor(session.pid)
        pkdSession.detached.connect(detached)

        try {
            console.log('dump extensions')
            const pids = await script.exports.launchAll()
            for (let pid of pids) {
                if (pid === 0) continue

                if (await pkdScript.exports.jetsam(pid) !== 0) {
                    throw new Error(`unable to unchain ${pid}`)
                }

                const pluginSession = await dev.attach(pid)
                const pluginScript = await pluginSession.createScript(js)
                pluginSession.detached.connect(detached)

                await pluginScript.load()
                await pluginScript.exports.prepare(c)
                const childHandler = new Handler(cwd, root)
                childHandler.connect(pluginScript)

                await pluginScript.exports.dump({executableOnly: true})
                await pluginScript.unload()
                await pluginSession.detach()
                await dev.kill(pid)
            }
            await pkdScript.unload()
            await pkdSession.detach()
        } catch (ex) {
            console.warn(chalk.redBright(`unable to dump plugins ${ex}`))
            console.warn(`Please file a bug to https://github.com/ChiChou/bagbak/issues`)
            console.warn(ex)
        }
    }

    if (handler.misc.warnAboutNTFS) {
        console.warn(chalk.yellow(`WARNING: Failed to update file timestamps. This is probably because you're 
      on Windows and using NTFS, which is incompatible with some file attributes.`))
    }

    await script.unload()
    await session.detach()

    console.log(chalk.green('Congrats!'))
    console.log('open', chalk.greenBright(parent))
}


const Device = require('./lib/device')
const program = require("commander");

const timeout = (time) => {
    return new Promise((resolve, reject) => {
        setTimeout(() => {
            resolve()
        }, time)
    })
}

function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); // $& means the whole matched string
}

function replaceAll(str, match, replacement) {
    return str.replace(new RegExp(escapeRegExp(match), 'g'), () => replacement);
}

const checkDownloaded = async (device, bundleId) => {
    while (!await device.exitApp(bundleId)) {
        await timeout(3000)
    }
}

async function main() {
    const program = require('commander')

    program
        .name('bagbak')
        .option('-l, --list', 'list apps')
        .option('-H, --host <host>', 'hostname (optional)')
        .option('-u, --uuid <uuid>', 'uuid of USB device (optional)')
        .option('-o, --output <output>', 'output directory', 'dump')
        .option('-f, --override', 'override existing')
        .option('-k, --kill', 'dump finish kill app')
        .option('-e, --executable-only', 'dump executables only')
        .option('-z, --zip', 'create zip archive (ipa)')
        .option('-n, --no-extension', 'do not dump extensions')
        .usage('[bundle id or name]')

    program.parse(process.argv)

    if (program.uuid && program.host)
        throw new Error('Use either uuid or host')

    if (program.args.length > 1)
        throw new Error('For stability, only decrypt one app once')

    if (program.list && program.args.length)
        throw new Error('Invalid command')

    let device = null
    if (program.uuid)
        device = await Device.find(program.uuid)
    else if (program.host)
        device = await Device.connect(program.host)
    else
        device = await Device.usb()

    // if (program.list) {
    //     const list = await device.dev.enumerateApplications()
    //     for (let app of list) {
    //         delete app.smallIcon
    //         delete app.largeIcon
    //     }
    //     list.sort((a, b) => (a.name.toLowerCase() > b.name.toLowerCase()) ? 1 : -1)
    //     console.table(list)
    //     return
    // }

    if (program.args.length === 1) {
        const app = program.args[0]
        const opt = Object.assign({app}, program)

        let baseUrl = 'http://192.168.3.4:3000'
        while (true) {
            let dumpInfoRes = await (await fetch(`${baseUrl}/automation/aritest/dump`)).json()
            if (!dumpInfoRes.data) {
                console.log('没有要处理的提取请求')
                await timeout(3000)
                continue
            }
            let dumpInfo = dumpInfoRes.data

            console.log('开始处理：', dumpInfo)

            console.log('检查appStore上的版本跟上传的版本是不是新的')
            let lookupResponse = await (await fetch(`https://itunes.apple.com/lookup?id=${dumpInfo.appid}&country=${dumpInfo.country}&_=${new Date().getTime()}`, {
                method: 'post',
                headers: {'Content-Type': 'application/json'}
            })).json()

            if (lookupResponse.results.length > 0) {
                let storeInfo = lookupResponse.results[0]
                if (storeInfo.version !== dumpInfo.version) {
                    console.error(chalk.red(`appStore上的最新版本为：${storeInfo.version} , 要提取的版本为：${dumpInfo.version} , 不满足最新版本需求，请检查。`))
                    break;
                } else {
                    console.log(chalk.green('版本是最新的，继续往下处理'))
                }
            } else {
                console.error(chalk.red('appStore不存在，请检查'))
                break;
            }

            let switchCountry = await (await fetch(`${baseUrl}/automation/aritest/switchCountry`)).json()
            console.log('切换是否已经切换 ->', switchCountry.data)
            while (switchCountry.data) {//是否已经切换地区
                // const safariSession = await device.run('com.apple.mobilesafari')//打开safari浏览器
                // await safariSession.detach()
                // await timeout(5000)//等待打开appStore
                // await device.dev.kill(safariSession.pid)

                //info
                let bundleId = dumpInfo.bundleId
                //

                let updateResponse = await (await fetch(`${baseUrl}/dump/update`, {
                    method: 'post',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        appid: dumpInfo.appid,
                        country: dumpInfo.country,
                        name: dumpInfo.mergeName,
                        lname: dumpInfo.name,
                        icon: dumpInfo.icon,
                        version: dumpInfo.version,
                        des: '官方版本',
                        latest: 1,
                        bundleId: dumpInfo.bundleId,
                        status: 1
                    })
                })).json()

                console.log('修改状态为提取中：', updateResponse)
                if (!updateResponse.data) {
                    console.error(chalk.red('修改状态异常，请检查'), updateResponse.msg)
                    return
                }


                //
                console.log('检查下载...', bundleId)
                await checkDownloaded(device, bundleId)
                console.log(chalk.green('下载完成'))
                const appSession = await device.run(bundleId)//打开pp
                console.log('app运行成功')
                shell.rm('-rf', path.join(program.output, bundleId))
                try {
                    await dump(device.dev, appSession, {
                        ...opt,
                        app: bundleId
                    })
                } catch (e) {
                    await (await fetch(dataConfig.notify,{
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: {
                            msgtype: 'markdown',
                            markdown: {
                                title: `${dumpInfo.name} 砸壳失败`,
                                text: JSON.stringify(dumpInfo)
                            }
                        }
                    })).json()
                    console.error(chalk.red('砸壳失败，请检查'), e)
                    return
                }
                await appSession.detach()
                await device.dev.kill(appSession.pid)
                if (program.zip) {
                    const tmp = path.join(path.join(__dirname, 'dump'), `"${dumpInfo.mergeName}_${dumpInfo.version}.zip"`)
                    const cwd = path.join(program.output, bundleId)
                    try {
                        await zip(tmp, 'Payload', cwd)
                    } catch (e) {
                        console.error('failed to create zip archive')
                        console.error(e)
                        return
                    }

                    const ipa = path.join(program.output, `${dumpInfo.mergeName}_${dumpInfo.version}.ipa`)
                    await fs.rename(path.join(program.output, `${dumpInfo.mergeName}_${dumpInfo.version}` + '.zip'), ipa)

                    console.log(`archive: ${chalk.blue(ipa)}`)

                    const ipaDir = dataConfig.ipaDirPath
                    const ipas = (await fse.readdir(ipaDir))
                    const convertIpas = ipas.map(fileName => {
                        let ipaFile = fsr.statSync(path.resolve(ipaDir, fileName))
                        return {
                            fileName, size: ipaFile.size, time: ipaFile.mtimeMs
                        };
                    })
                        .filter(item => {
                            return item.fileName && !item.fileName.startsWith('ipadump.com');
                        });
                    if (convertIpas.length === 0) {
                        console.error(chalk.red('不存在未上传文件'))
                        return false;
                    }
                    convertIpas.sort((b, a) => {
                        return a.time - b.time
                    });

                    // shell.exec(`tidevice uninstall ${bundleId}`).stdout//删除app,不建议添加，怕上传失败，每天批量一波即可

                    let latestDumpIpa = convertIpas[0]
                    console.log('检查帐号登录情况')
                    if (shell.exec(`${dataConfig.aliyunpan} who`).stdout.includes("未登录帐号")) {
                        console.log('登录...')
                        shell.exec(`${dataConfig.aliyunpan} login --RefreshToken ${dataConfig.token}`).stdout
                    }
                    shell.exec(`${dataConfig.aliyunpan} mkdir "/ipadump/ipas/${dumpInfo.country}/${dumpInfo.appid}"`).stdout //创建目录
                    let latestFileName = `ipadump.com_${dumpInfo.mergeName}_${dumpInfo.version}.ipa`
                    let newIpaPath = path.resolve(ipaDir, latestFileName)
                    if (`${latestFileName}` !== latestDumpIpa.fileName) {
                        console.log(chalk.yellow(`${latestFileName} 跟 ${latestDumpIpa.fileName} 不相同，重新命名`))
                        let oldIpaPath = path.resolve(ipaDir, latestDumpIpa.fileName).toString()
                        await fs.rename(oldIpaPath, newIpaPath)
                    }
                    let ipadumpIpaPath = path.resolve(ipaDir, latestFileName)
                    // console.log('计算文件hash中...')
                    // let fileHash = await calculateHash(ipadumpIpaPath)
                    // console.log(chalk.green(`文件hash：${fileHash}`))
                    // let fileResult = shell.exec(`"${dataConfig.aliyunpan}" ll "/ipadump/ipas/${dumpInfo.country}/${dumpInfo.appid}/${latestFileName}"`).stdout
                    // if (!fileResult.trim()) {
                    //     console.log(chalk.red('读取云盘路径异常'))
                    //     return
                    // }
                    // let exitFile = fileResult.includes(fileHash.toUpperCase())
                    // console.log('文件是否已经上传过：', exitFile)
                    // if (!exitFile) {
                    shell.exec(`${dataConfig.aliyunpan} upload "${ipadumpIpaPath.replace(' ', ' ')}" "/ipadump/ipas/${dumpInfo.country}/${dumpInfo.appid}" --ow`).stdout
                    // } else {
                    //     console.log(chalk.yellow('文件已经存在，不需要上传'))
                    // }

                    let updateResponse2 = await (await fetch(`${baseUrl}/dump/update`, {
                        method: 'post',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            appid: dumpInfo.appid,
                            country: dumpInfo.country,
                            name: dumpInfo.mergeName,
                            lname: dumpInfo.name,
                            version: dumpInfo.version,
                            icon: dumpInfo.icon,
                            des: '官方版本',
                            latest: 1,
                            bundleId: dumpInfo.bundleId,
                            status: 2
                        })
                    })).json()
                    console.log('修改状态为提取完成：', updateResponse2)
                    if (!updateResponse2.data) {
                        console.error(chalk.red('修改状态异常，请检查'), updateResponse2.msg)
                        return
                    }

                    let f = await fs.stat(ipadumpIpaPath)
                    let upsertResponse = await (await fetch(`${baseUrl}/version/upsert`, {
                        method: 'post',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            appid: dumpInfo.appid,
                            version: dumpInfo.version,
                            country: dumpInfo.country,
                            push: 1,
                            download: 0,
                            size: f.size,
                            official: 1,
                            des: `官方版本`,
                            file: `https://api.ipadump.com/file/pan/download?fileId=&appid=${dumpInfo.appid}&country=${dumpInfo.country}&fileName=ipadump.com_${dumpInfo.mergeName}_${dumpInfo.version}.ipa`
                        })
                    })).json()
                    if (!upsertResponse.data) {
                        console.error(chalk.red('版本增加异常，请检查'), upsertResponse.msg)
                        return
                    } else {
                        console.log(chalk.green(`${dumpInfo.mergeName} ${dumpInfo.version} 版本增加成功`))
                    }
                    console.log('文件删除')
                    shell.rm('-rf', cwd)
                    await fs.rm(ipadumpIpaPath)
                    console.log(chalk.green(`${ipadumpIpaPath} 文件删除成功`))

                    console.log('修改提取完成状态')
                    let dumpFinishResponse = await (await fetch(`${baseUrl}/automation/bagbak/dumpFinish`, {
                        method: 'post',
                        headers: {'Content-Type': 'application/json'},
                    })).json()
                    if (!dumpFinishResponse.data) {
                        console.error(chalk.red('修改提取完成状态异常，请检查'), dumpFinishResponse.msg)
                        return
                    } else {
                        console.log(chalk.green('提取状态完成，开始处理下一个请求'))
                    }
                }
                //开始砸壳上传
                break
            }
            await timeout(3000)
            // break;
        }

    }

}


main().catch(e => {
    console.error(chalk.red('FATAL ERROR'))
    console.error(e)
    process.exit()
})
