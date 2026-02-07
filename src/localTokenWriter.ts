import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { execSync } from 'child_process';
import initSqlJs from 'sql.js';

export interface WriteResult {
    success: boolean;
    error?: string;
}

/**
 * 本地 Token 写入器
 * 将 accessToken 加密后写入 Windsurf 的 state.vscdb
 */
export class LocalTokenWriter {
    private dbPath: string;
    private localStatePath: string;
    private logger: (msg: string) => void;

    constructor(logger?: (msg: string) => void) {
        const appData = process.env.APPDATA || '';
        this.dbPath = path.join(appData, 'Windsurf', 'User', 'globalStorage', 'state.vscdb');
        this.localStatePath = path.join(appData, 'Windsurf', 'Local State');
        this.logger = logger || console.log;
    }

    /**
     * 使用 accessToken 登录
     * @param accessToken sk-ws-01-xxx 格式的 token
     * @param accountName 账户名称
     */
    public async loginWithAccessToken(accessToken: string, accountName: string): Promise<WriteResult> {
        try {
            this.logger('[Token写入] 开始写入 accessToken...');

            // 检查文件是否存在
            if (!fs.existsSync(this.dbPath)) {
                return { success: false, error: `数据库文件不存在: ${this.dbPath}` };
            }
            if (!fs.existsSync(this.localStatePath)) {
                return { success: false, error: `Local State 文件不存在: ${this.localStatePath}` };
            }

            // 获取加密密钥
            const keyResult = await this.getEncryptionKey();
            if (!keyResult.key) {
                return { success: false, error: `获取加密密钥失败: ${keyResult.error}` };
            }
            const key = keyResult.key;
            this.logger(`[Token写入] 获取密钥成功: ${key.length} 字节`);

            // 构建 session 数据
            const sessionData = [{
                id: crypto.randomUUID(),
                accessToken: accessToken,
                account: {
                    label: accountName,
                    id: accountName
                },
                scopes: []
            }];
            const sessionJson = JSON.stringify(sessionData);
            this.logger(`[Token写入] Session 数据长度: ${sessionJson.length}`);

            // 加密 session 数据
            const encryptedData = this.encryptSession(sessionJson, key);
            if (!encryptedData) {
                return { success: false, error: '加密 Session 失败' };
            }
            this.logger(`[Token写入] 加密数据长度: ${encryptedData.length} 字节`);

            // 写入数据库
            const writeResult = await this.writeToDatabase(encryptedData, accountName);
            if (!writeResult.success) {
                return writeResult;
            }

            this.logger('[Token写入] ✓ 写入成功！请重启 Windsurf 以生效');
            return { success: true };
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.logger(`[Token写入] ✗ 错误: ${message}`);
            return { success: false, error: message };
        }
    }

    /**
     * 从 Local State 获取并解密 AES 密钥
     */
    private async getEncryptionKey(): Promise<{ key: Buffer | null; error?: string }> {
        try {
            this.logger(`[获取密钥] 读取 Local State: ${this.localStatePath}`);
            
            if (!fs.existsSync(this.localStatePath)) {
                return { key: null, error: `Local State 文件不存在: ${this.localStatePath}` };
            }
            
            const localStateContent = fs.readFileSync(this.localStatePath, 'utf8');
            let localState;
            try {
                localState = JSON.parse(localStateContent);
            } catch (parseError) {
                return { key: null, error: `Local State JSON 解析失败: ${parseError}` };
            }
            
            const encryptedKeyB64 = localState?.os_crypt?.encrypted_key;
            if (!encryptedKeyB64) {
                this.logger('[获取密钥] Local State 内容: ' + JSON.stringify(Object.keys(localState || {})));
                return { key: null, error: 'Local State 中没有 os_crypt.encrypted_key 字段' };
            }

            // Base64 解码
            const encryptedKey = Buffer.from(encryptedKeyB64, 'base64');
            this.logger(`[获取密钥] 加密密钥长度: ${encryptedKey.length} 字节`);
            
            // 检查是否有 DPAPI 前缀
            const prefix = encryptedKey.slice(0, 5).toString('utf8');
            if (prefix !== 'DPAPI') {
                return { key: null, error: `密钥前缀不是 DPAPI，实际是: ${prefix}` };
            }
            
            // 移除 "DPAPI" 前缀 (5 bytes)
            const keyWithoutPrefix = encryptedKey.slice(5);

            // 使用 PowerShell 调用 DPAPI 解密
            const decryptResult = await this.decryptWithDPAPI(keyWithoutPrefix);
            if (!decryptResult.key) {
                return { key: null, error: `DPAPI 解密失败: ${decryptResult.error}` };
            }
            
            return { key: decryptResult.key };
        } catch (error) {
            this.logger(`[获取密钥] 错误: ${error}`);
            return { key: null, error: String(error) };
        }
    }

    /**
     * 使用 Windows DPAPI 解密数据
     */
    private async decryptWithDPAPI(encryptedData: Buffer): Promise<{ key: Buffer | null; error?: string }> {
        try {
            const tempDir = process.env.TEMP || process.env.TMP || 'C:\\Windows\\Temp';
            const timestamp = Date.now();
            const scriptPath = path.join(tempDir, `dpapi_${timestamp}.ps1`);
            const dataPath = path.join(tempDir, `dpapi_data_${timestamp}.txt`);
            const outputPath = path.join(tempDir, `dpapi_out_${timestamp}.txt`);
            
            const encryptedB64 = encryptedData.toString('base64');
            
            // 将 Base64 数据写入单独文件，避免命令行长度和编码问题
            fs.writeFileSync(dataPath, encryptedB64, 'utf8');
            
            // PowerShell 脚本 - 从文件读取数据
            const scriptContent = `
Add-Type -AssemblyName System.Security
try {
    $encryptedB64 = Get-Content -Path '${dataPath.replace(/\\/g, '\\\\')}' -Raw
    $encryptedBytes = [Convert]::FromBase64String($encryptedB64)
    $decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encryptedBytes, 
        $null, 
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    $result = [Convert]::ToBase64String($decryptedBytes)
    [System.IO.File]::WriteAllText('${outputPath.replace(/\\/g, '\\\\')}', $result)
} catch {
    [System.IO.File]::WriteAllText('${outputPath.replace(/\\/g, '\\\\')}', "ERROR: $($_.Exception.Message)")
}
`;
            // 写入脚本文件 (UTF-8 with BOM for PowerShell)
            const bom = Buffer.from([0xEF, 0xBB, 0xBF]);
            fs.writeFileSync(scriptPath, Buffer.concat([bom, Buffer.from(scriptContent, 'utf8')]));
            
            this.logger(`[DPAPI解密] 脚本: ${scriptPath}`);
            
            try {
                execSync(`powershell -NoProfile -ExecutionPolicy Bypass -File "${scriptPath}"`, {
                    windowsHide: true,
                    timeout: 15000
                });
            } catch (execError: any) {
                this.logger(`[DPAPI解密] PowerShell 错误: ${execError.message}`);
                // 继续检查输出文件，可能脚本执行成功但 execSync 报错
            }
            
            // 清理临时文件
            const cleanup = () => {
                try { fs.unlinkSync(scriptPath); } catch {}
                try { fs.unlinkSync(dataPath); } catch {}
            };
            
            if (fs.existsSync(outputPath)) {
                const result = fs.readFileSync(outputPath, 'utf8').trim();
                try { fs.unlinkSync(outputPath); } catch {}
                cleanup();
                
                if (!result) {
                    return { key: null, error: '解密结果为空' };
                }
                
                if (result.startsWith('ERROR:')) {
                    return { key: null, error: result };
                }
                
                this.logger(`[DPAPI解密] 成功，密钥长度: ${Buffer.from(result, 'base64').length}`);
                return { key: Buffer.from(result, 'base64') };
            }
            
            cleanup();
            return { key: null, error: '输出文件未生成，PowerShell 可能执行失败' };
        } catch (error) {
            this.logger(`[DPAPI解密] 错误: ${error}`);
            return { key: null, error: String(error) };
        }
    }

    /**
     * 加密 session 数据 (Chromium v10 格式)
     */
    private encryptSession(data: string, key: Buffer): Buffer | null {
        try {
            // 生成 12 字节随机 nonce
            const nonce = crypto.randomBytes(12);
            
            // AES-256-GCM 加密
            const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
            const encrypted = Buffer.concat([
                cipher.update(data, 'utf8'),
                cipher.final()
            ]);
            const tag = cipher.getAuthTag();
            
            // v10 格式: "v10" (3字节) + nonce (12字节) + 密文 + tag (16字节)
            const result = Buffer.concat([
                Buffer.from('v10', 'utf8'),
                nonce,
                encrypted,
                tag
            ]);
            
            return result;
        } catch (error) {
            this.logger(`[加密Session] 错误: ${error}`);
            return null;
        }
    }

    /**
     * 写入加密数据到数据库
     */
    private async writeToDatabase(encryptedData: Buffer, accountName: string): Promise<WriteResult> {
        try {
            // 初始化 sql.js
            const SQL = await initSqlJs();
            
            // 读取数据库
            const dbBuffer = fs.readFileSync(this.dbPath);
            const db = new SQL.Database(dbBuffer);
            
            // 构建 JSON Buffer 格式的值
            const bufferValue = JSON.stringify({
                type: 'Buffer',
                data: Array.from(encryptedData)
            });
            
            // 定义需要写入的键
            const sessionKey = 'secret://{"extensionId":"codeium.windsurf","key":"windsurf_auth.sessions"}';
            const authKey = 'codeium.windsurf-windsurf_auth';
            
            // 写入 session 数据
            db.run(
                "INSERT OR REPLACE INTO ItemTable (key, value) VALUES (?, ?)",
                [sessionKey, bufferValue]
            );
            this.logger(`[写入数据库] ✓ 写入 session 数据`);
            
            // 写入当前账户名
            db.run(
                "INSERT OR REPLACE INTO ItemTable (key, value) VALUES (?, ?)",
                [authKey, JSON.stringify(accountName)]
            );
            this.logger(`[写入数据库] ✓ 写入账户名: ${accountName}`);
            
            // 导出并保存数据库
            const newDbBuffer = db.export();
            db.close();
            
            // 备份原数据库
            const backupPath = this.dbPath + '.backup_' + Date.now();
            fs.copyFileSync(this.dbPath, backupPath);
            this.logger(`[写入数据库] ✓ 备份原数据库: ${backupPath}`);
            
            // 写入新数据库
            fs.writeFileSync(this.dbPath, Buffer.from(newDbBuffer));
            this.logger(`[写入数据库] ✓ 保存新数据库`);
            
            return { success: true };
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.logger(`[写入数据库] 错误: ${message}`);
            return { success: false, error: message };
        }
    }
}
