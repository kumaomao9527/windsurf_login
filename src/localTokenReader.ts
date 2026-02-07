import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { execSync } from 'child_process';
import initSqlJs, { Database } from 'sql.js';

export interface LocalSession {
    id: string;
    accessToken: string;
    account: {
        label: string;
        id: string;
    };
    scopes: string[];
}

export interface LocalAccountInfo {
    accountName: string;
    session?: LocalSession;
    error?: string;
}

/**
 * 本地 Token 读取器
 * 从 Windsurf 的 state.vscdb 读取并解密 Session Token
 */
export class LocalTokenReader {
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
     * 获取本地已登录账户的 accessToken
     */
    public async getLocalToken(): Promise<LocalAccountInfo> {
        try {
            this.logger('[本地Token] 开始读取本地账户信息...');

            // 检查文件是否存在
            if (!fs.existsSync(this.dbPath)) {
                return { accountName: '', error: `数据库文件不存在: ${this.dbPath}` };
            }
            if (!fs.existsSync(this.localStatePath)) {
                return { accountName: '', error: `Local State 文件不存在: ${this.localStatePath}` };
            }

            // 初始化 sql.js
            const SQL = await initSqlJs();
            
            // 复制数据库到临时位置（避免锁定问题）
            const tempDbPath = path.join(process.env.TEMP || '', `windsurf_state_${Date.now()}.vscdb`);
            fs.copyFileSync(this.dbPath, tempDbPath);
            
            const dbBuffer = fs.readFileSync(tempDbPath);
            const db = new SQL.Database(dbBuffer);
            
            // 清理临时文件
            try { fs.unlinkSync(tempDbPath); } catch {}

            // 读取当前账户名
            const accountName = this.readCurrentAccountNameFromDb(db);
            if (!accountName) {
                db.close();
                return { accountName: '', error: '未找到已登录的账户' };
            }
            this.logger(`[本地Token] 当前账户: ${accountName}`);

            // 读取加密的 session 数据
            const encryptedSession = this.readEncryptedSessionFromDb(db);
            db.close();
            
            if (!encryptedSession) {
                return { accountName, error: '未找到加密的 Session 数据' };
            }
            this.logger(`[本地Token] 读取到加密数据: ${encryptedSession.length} 字节`);

            // 获取解密密钥
            const key = await this.getEncryptionKey();
            if (!key) {
                return { accountName, error: '获取解密密钥失败' };
            }
            this.logger(`[本地Token] 获取密钥成功: ${key.length} 字节`);

            // 解密 session
            const session = this.decryptSession(encryptedSession, key);
            if (!session) {
                return { accountName, error: '解密 Session 失败' };
            }
            this.logger(`[本地Token] ✓ 解密成功! AccessToken: ${session.accessToken.substring(0, 20)}...`);

            return { accountName, session };
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.logger(`[本地Token] ✗ 错误: ${message}`);
            return { accountName: '', error: message };
        }
    }

    /**
     * 从数据库读取当前账户名
     */
    private readCurrentAccountNameFromDb(db: Database): string | null {
        try {
            const result = db.exec("SELECT value FROM ItemTable WHERE key = 'codeium.windsurf-windsurf_auth'");
            if (result.length > 0 && result[0].values.length > 0) {
                const value = result[0].values[0][0];
                if (typeof value === 'string') {
                    // 值可能是 JSON 字符串 "accountName" 或直接的账户名
                    try {
                        return JSON.parse(value);
                    } catch {
                        return value;
                    }
                }
            }
            return null;
        } catch (error) {
            this.logger(`[读取账户名] 错误: ${error}`);
            return null;
        }
    }

    /**
     * 从数据库读取加密的 session 数据
     */
    private readEncryptedSessionFromDb(db: Database): Buffer | null {
        try {
            // 查找包含 windsurf_auth.sessions 的 secret 键
            const result = db.exec("SELECT key, value FROM ItemTable WHERE key LIKE '%secret%' AND key LIKE '%windsurf_auth%'");
            
            this.logger(`[读取Session] 找到 ${result.length > 0 ? result[0].values.length : 0} 条 secret 记录`);
            
            if (result.length > 0) {
                for (const row of result[0].values) {
                    const key = row[0] as string;
                    const value = row[1];
                    
                    this.logger(`[读取Session] 键: ${key}`);
                    
                    if (key.includes('windsurf_auth.sessions')) {
                        if (typeof value === 'string') {
                            // 尝试解析 JSON Buffer 格式
                            try {
                                const parsed = JSON.parse(value);
                                if (parsed.type === 'Buffer' && Array.isArray(parsed.data)) {
                                    return Buffer.from(parsed.data);
                                }
                            } catch {
                                // 可能是直接的字符串
                                this.logger(`[读取Session] 值不是 Buffer JSON 格式`);
                            }
                        } else if (value instanceof Uint8Array) {
                            return Buffer.from(value);
                        }
                    }
                }
            }
            
            // 备用：尝试更宽泛的搜索
            const result2 = db.exec("SELECT key, value FROM ItemTable WHERE key LIKE '%session%'");
            this.logger(`[读取Session] 备用搜索找到 ${result2.length > 0 ? result2[0].values.length : 0} 条记录`);
            
            if (result2.length > 0) {
                for (const row of result2[0].values) {
                    const key = row[0] as string;
                    this.logger(`[读取Session] 备用键: ${key}`);
                }
            }
            
            return null;
        } catch (error) {
            this.logger(`[读取Session] 错误: ${error}`);
            return null;
        }
    }

    /**
     * 从 Local State 获取并解密 AES 密钥
     */
    private async getEncryptionKey(): Promise<Buffer | null> {
        try {
            const localStateContent = fs.readFileSync(this.localStatePath, 'utf8');
            const localState = JSON.parse(localStateContent);
            
            const encryptedKeyB64 = localState?.os_crypt?.encrypted_key;
            if (!encryptedKeyB64) {
                this.logger('[获取密钥] Local State 中没有 encrypted_key');
                return null;
            }

            // Base64 解码
            const encryptedKey = Buffer.from(encryptedKeyB64, 'base64');
            
            // 移除 "DPAPI" 前缀 (5 bytes)
            const keyWithoutPrefix = encryptedKey.slice(5);

            // 使用 PowerShell 调用 DPAPI 解密
            const decryptedKey = await this.decryptWithDPAPI(keyWithoutPrefix);
            return decryptedKey;
        } catch (error) {
            this.logger(`[获取密钥] 错误: ${error}`);
            return null;
        }
    }

    /**
     * 使用 Windows DPAPI 解密数据
     */
    private async decryptWithDPAPI(encryptedData: Buffer): Promise<Buffer | null> {
        try {
            // 将加密数据转换为 Base64
            const encryptedB64 = encryptedData.toString('base64');
            this.logger(`[DPAPI解密] 加密数据长度: ${encryptedData.length} 字节`);
            
            // PowerShell 脚本调用 DPAPI - 使用更简洁的写法避免引号问题
            const psScript = `Add-Type -AssemblyName System.Security; $e = [Convert]::FromBase64String('${encryptedB64}'); $d = [System.Security.Cryptography.ProtectedData]::Unprotect($e, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser); [Convert]::ToBase64String($d)`;

            const result = execSync(`powershell -NoProfile -NonInteractive -Command "${psScript}"`, {
                encoding: 'utf8',
                windowsHide: true,
                timeout: 10000
            }).trim();

            this.logger(`[DPAPI解密] 解密结果长度: ${result.length}`);
            
            if (!result || result.length === 0) {
                this.logger('[DPAPI解密] 解密结果为空');
                return null;
            }

            return Buffer.from(result, 'base64');
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.logger(`[DPAPI解密] 错误: ${message}`);
            
            // 尝试备用方法：使用 PowerShell 文件
            return this.decryptWithDPAPIFile(encryptedData);
        }
    }

    /**
     * 备用方法：通过临时 PowerShell 脚本文件解密
     */
    private decryptWithDPAPIFile(encryptedData: Buffer): Buffer | null {
        try {
            this.logger('[DPAPI解密] 尝试备用方法...');
            
            const tempDir = process.env.TEMP || '';
            const scriptPath = path.join(tempDir, `dpapi_decrypt_${Date.now()}.ps1`);
            const outputPath = path.join(tempDir, `dpapi_output_${Date.now()}.txt`);
            
            const encryptedB64 = encryptedData.toString('base64');
            
            const scriptContent = `
Add-Type -AssemblyName System.Security
try {
    $encryptedBytes = [Convert]::FromBase64String('${encryptedB64}')
    $decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encryptedBytes, 
        $null, 
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    [Convert]::ToBase64String($decryptedBytes) | Out-File -FilePath '${outputPath.replace(/\\/g, '\\\\')}' -NoNewline
} catch {
    "ERROR: $($_.Exception.Message)" | Out-File -FilePath '${outputPath.replace(/\\/g, '\\\\')}' -NoNewline
}
`;
            
            fs.writeFileSync(scriptPath, scriptContent, 'utf8');
            
            execSync(`powershell -NoProfile -ExecutionPolicy Bypass -File "${scriptPath}"`, {
                windowsHide: true,
                timeout: 10000
            });
            
            // 读取输出
            if (fs.existsSync(outputPath)) {
                const result = fs.readFileSync(outputPath, 'utf8').trim();
                
                // 清理临时文件
                try { fs.unlinkSync(scriptPath); } catch {}
                try { fs.unlinkSync(outputPath); } catch {}
                
                if (result.startsWith('ERROR:')) {
                    this.logger(`[DPAPI解密] 备用方法错误: ${result}`);
                    return null;
                }
                
                this.logger(`[DPAPI解密] 备用方法成功，结果长度: ${result.length}`);
                return Buffer.from(result, 'base64');
            }
            
            return null;
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.logger(`[DPAPI解密] 备用方法错误: ${message}`);
            return null;
        }
    }

    /**
     * 解密 Chromium v10 加密的 session 数据
     */
    private decryptSession(encryptedData: Buffer, key: Buffer): LocalSession | null {
        try {
            this.logger(`[解密Session] 加密数据长度: ${encryptedData.length}, 密钥长度: ${key.length}`);
            this.logger(`[解密Session] 加密数据前20字节: ${encryptedData.slice(0, 20).toString('hex')}`);
            
            // 检查 v10/v11 前缀
            const prefix = encryptedData.slice(0, 3).toString('utf8');
            this.logger(`[解密Session] 前缀: "${prefix}" (hex: ${encryptedData.slice(0, 3).toString('hex')})`);
            
            if (prefix !== 'v10' && prefix !== 'v11') {
                // 可能数据不是以 v10 开头，尝试查找 v10 位置
                const v10Index = encryptedData.indexOf('v10');
                const v11Index = encryptedData.indexOf('v11');
                this.logger(`[解密Session] v10位置: ${v10Index}, v11位置: ${v11Index}`);
                
                if (v10Index > 0) {
                    this.logger(`[解密Session] 尝试从位置 ${v10Index} 开始解密`);
                    return this.decryptSession(encryptedData.slice(v10Index), key);
                }
                if (v11Index > 0) {
                    this.logger(`[解密Session] 尝试从位置 ${v11Index} 开始解密`);
                    return this.decryptSession(encryptedData.slice(v11Index), key);
                }
                
                this.logger(`[解密Session] 未知的加密版本: ${prefix}`);
                return null;
            }

            // v10 格式: v10 (3字节) + nonce (12字节) + 密文 + tag (16字节)
            const nonce = encryptedData.slice(3, 15);
            const ciphertextWithTag = encryptedData.slice(15);
            const tag = ciphertextWithTag.slice(-16);
            const ciphertext = ciphertextWithTag.slice(0, -16);
            
            this.logger(`[解密Session] nonce长度: ${nonce.length}, 密文长度: ${ciphertext.length}, tag长度: ${tag.length}`);

            // AES-256-GCM 解密
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
            decipher.setAuthTag(tag);
            
            const decrypted = Buffer.concat([
                decipher.update(ciphertext),
                decipher.final()
            ]);

            const decryptedStr = decrypted.toString('utf8');
            this.logger(`[解密Session] 解密成功! 内容长度: ${decryptedStr.length}`);
            this.logger(`[解密Session] 解密内容前100字符: ${decryptedStr.substring(0, 100)}`);

            // 解析 JSON
            const sessions = JSON.parse(decryptedStr);
            
            if (Array.isArray(sessions) && sessions.length > 0) {
                const session = sessions[0] as LocalSession;
                this.logger(`[解密Session] ✓ 获取到 accessToken: ${session.accessToken?.substring(0, 20)}...`);
                return session;
            }

            this.logger(`[解密Session] 解析结果为空或格式不正确`);
            return null;
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.logger(`[解密Session] 解密错误: ${message}`);
            return null;
        }
    }
}
