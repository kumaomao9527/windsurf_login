import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { WindsurfInjector, UsageInfo } from './windsurfInjector';
import { MachineIdResetter } from './machineIdResetter';
import { LocalTokenReader } from './localTokenReader';
import { LocalTokenWriter } from './localTokenWriter';

interface Account {
    email: string;
    password: string;
    displayName?: string;
    localId?: string;
    idToken?: string;
    refreshToken?: string;
    expiresAt?: number;
    usageInfo?: UsageInfo;
    accessToken?: string;
    isAccessToken?: boolean;
}

interface AccountsData {
    accounts: Account[];
    currentAccountId?: string;
}

const API_KEY = 'AIzaSyDsOl-1XpT5err0Tcnx8FFod1H8gVGIycY';
const AUTH_URL = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${API_KEY}`;
const REFRESH_URL = `https://securetoken.googleapis.com/v1/token?key=${API_KEY}`;

export class LoginViewProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'windsurf-login.loginView';
    private _view?: vscode.WebviewView;
    private _accounts: Account[] = [];
    private _currentAccountIndex: number = -1;
    private _accountsFilePath: string;
    private _injector: WindsurfInjector;
    private _usageInfo: UsageInfo | null = null;
    private _resetter: MachineIdResetter;
    private _tokenReader: LocalTokenReader;
    private _tokenWriter: LocalTokenWriter;
    private _localToken: string | null = null;

    constructor(
        private readonly _extensionUri: vscode.Uri,
        private readonly _context: vscode.ExtensionContext
    ) {
        // 使用 globalStorageUri 存储账户信息，避免插件更新时丢失
        const globalStoragePath = _context.globalStorageUri.fsPath;
        if (!fs.existsSync(globalStoragePath)) {
            fs.mkdirSync(globalStoragePath, { recursive: true });
        }
        this._accountsFilePath = path.join(globalStoragePath, 'accounts.json');
        this._injector = new WindsurfInjector();
        this._resetter = new MachineIdResetter();
        this._tokenReader = new LocalTokenReader((msg) => this._injector.log(msg));
        this._tokenWriter = new LocalTokenWriter((msg) => this._injector.log(msg));
        
        // 迁移旧数据（从 undefined_publisher 路径）
        this._migrateOldData();
        
        this._loadAccounts();
    }

    private _loadAccounts() {
        try {
            if (fs.existsSync(this._accountsFilePath)) {
                const data = fs.readFileSync(this._accountsFilePath, 'utf-8');
                const parsed = JSON.parse(data);
                this._accounts = Array.isArray(parsed) ? parsed : (parsed.accounts || []);
                if (parsed.currentAccountId) {
                    this._currentAccountIndex = this._accounts.findIndex(a => a.localId === parsed.currentAccountId || a.email === parsed.currentAccountId);
                }
                this._injector.log(`[加载账户] ✓ 成功加载 ${this._accounts.length} 个账户`);
            } else {
                this._injector.log(`[加载账户] ⚠ 账户文件不存在`);
            }
        } catch (error) {
            this._injector.log(`[加载账户] ✗ 失败: ${error instanceof Error ? error.message : '未知错误'}`);
            this._accounts = [];
        }
    }

    private _saveAccounts() {
        const data: AccountsData = {
            accounts: this._accounts,
            currentAccountId: this._currentAccountIndex >= 0 
                ? this._accounts[this._currentAccountIndex]?.localId || this._accounts[this._currentAccountIndex]?.email
                : undefined
        };
        fs.writeFileSync(this._accountsFilePath, JSON.stringify(data, null, 2), 'utf-8');
    }

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        _resolveContext: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ) {
        this._view = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this._extensionUri]
        };

        webviewView.webview.html = this._getHtmlForWebview();

        webviewView.webview.onDidReceiveMessage(async (data) => {
            switch (data.type) {
                case 'addAccount':
                    await this._addAccount(data.email, data.password);
                    break;
                case 'deleteAccount':
                    this._deleteAccount(data.index);
                    break;
                case 'switchAccount':
                    await this._switchAccount(data.index);
                    break;
                case 'showLog':
                    this._injector.showLog();
                    break;
                case 'refreshToken':
                    await this._handleRefreshToken(data.index);
                    break;
                case 'refreshUsage':
                    await this._refreshUsage();
                    break;
                case 'resetMachineId':
                    await this._handleResetMachineId();
                    break;
                case 'batchAddAccounts':
                    await this._batchAddAccounts(data.accounts);
                    break;
                case 'refreshAllUsage':
                    await this._refreshAllUsage();
                    break;
                case 'openAccountsFolder':
                    this._openAccountsFolder();
                    break;
                case 'loginWithToken':
                    await this._loginWithToken(data.token, data.name);
                    break;
                case 'addAccessTokenAccount':
                    await this._addAccessTokenAccount(data.token, data.name);
                    break;
                case 'getLocalToken':
                    await this._handleGetLocalToken();
                    break;
                case 'copyLocalToken':
                    await this._copyLocalToken();
                    break;
                case 'useLocalToken':
                    await this._useLocalToken();
                    break;
            }
        });
    }

    private async _addAccount(email: string, password: string) {
        try {
            // 检查是否已存在
            const existingIndex = this._accounts.findIndex(a => a.email === email);
            if (existingIndex >= 0) {
                this._hideLoading();
                vscode.window.showWarningMessage(`账户 ${email} 已存在，已跳过`);
                return;
            }

            this._sendSimpleLoading('正在登录...');
            
            const response = await fetch(AUTH_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password, returnSecureToken: true })
            });

            if (!response.ok) {
                const error = await response.json() as { error?: { message?: string } };
                throw new Error(error.error?.message || '登录失败');
            }

            this._sendSimpleLoading('验证成功，正在保存...');

            const data = await response.json() as {
                email: string;
                displayName?: string;
                localId: string;
                idToken: string;
                refreshToken: string;
                expiresIn?: string;
            };
            
            const account: Account = {
                email: data.email,
                password,
                displayName: data.displayName,
                localId: data.localId,
                idToken: data.idToken,
                refreshToken: data.refreshToken,
                expiresAt: Date.now() + (parseInt(data.expiresIn || '3600') * 1000)
            };

            this._accounts.push(account);
            
            this._saveAccounts();
            this._hideLoading();
            this._updateView();
            vscode.window.showInformationMessage(`账户 ${data.displayName || email} 登录成功`);
        } catch (error: unknown) {
            this._hideLoading();
            const message = error instanceof Error ? error.message : '登录失败';
            vscode.window.showErrorMessage(`登录失败: ${message}`);
        }
    }

    private _deleteAccount(index: number) {
        const removed = this._accounts.splice(index, 1);
        if (this._currentAccountIndex === index) {
            this._currentAccountIndex = -1;
        } else if (this._currentAccountIndex > index) {
            this._currentAccountIndex--;
        }
        this._saveAccounts();
        this._updateView();
        vscode.window.showInformationMessage(`账户 ${removed[0]?.email} 已删除`);
    }

    private async _batchAddAccounts(accounts: Array<{ email: string; password: string }>) {
        if (!accounts || accounts.length === 0) {
            return;
        }

        let successCount = 0;
        let failCount = 0;
        let skipCount = 0;
        const total = accounts.length;
        const failedAccounts: Array<{ email: string; reason: string }> = [];

        this._injector.log(`[批量添加] 开始处理 ${total} 个账户`);
        this._sendSimpleLoading(`正在批量添加账户 (0/${total})...`);

        for (let i = 0; i < accounts.length; i++) {
            const { email, password } = accounts[i];
            this._sendSimpleLoading(`正在添加 ${email} (${i + 1}/${total})...`);

            // 检查是否已存在
            const existingIndex = this._accounts.findIndex(a => a.email === email);
            if (existingIndex >= 0) {
                this._injector.log(`[批量添加] ⊙ ${email} - 已存在`);
                skipCount++;
                continue;
            }

            try {
                const response = await fetch(AUTH_URL, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password, returnSecureToken: true })
                });

                if (!response.ok) {
                    const errorData = await response.json() as { error?: { message?: string } };
                    const reason = errorData.error?.message || `HTTP ${response.status}`;
                    failedAccounts.push({ email, reason });
                    this._injector.log(`[批量添加] ✗ ${email} - ${reason}`);
                    failCount++;
                    continue;
                }

                const data = await response.json() as {
                    email: string;
                    displayName?: string;
                    localId: string;
                    idToken: string;
                    refreshToken: string;
                    expiresIn?: string;
                };

                const account: Account = {
                    email: data.email,
                    password,
                    displayName: data.displayName,
                    localId: data.localId,
                    idToken: data.idToken,
                    refreshToken: data.refreshToken,
                    expiresAt: Date.now() + (parseInt(data.expiresIn || '3600') * 1000)
                };

                this._accounts.push(account);
                this._injector.log(`[批量添加] ✓ ${email}`);
                successCount++;
            } catch (error) {
                const reason = error instanceof Error ? error.message : '未知错误';
                failedAccounts.push({ email, reason });
                this._injector.log(`[批量添加] ✗ ${email} - ${reason}`);
                failCount++;
            }
        }

        this._injector.log(`[批量添加] 完成 - 成功 ${successCount} | 失败 ${failCount} | 跳过 ${skipCount}`);
        if (failedAccounts.length > 0) {
            this._injector.log(`[批量添加] 失败列表:`);
            for (const { email, reason } of failedAccounts) {
                this._injector.log(`  ✗ ${email} - ${reason}`);
            }
        }

        this._saveAccounts();
        this._hideLoading();
        this._updateView();

        const message = `批量添加完成：成功 ${successCount} 个${skipCount > 0 ? `，跳过 ${skipCount} 个` : ''}${failCount > 0 ? `，失败 ${failCount} 个（查看日志）` : ''}`;
        if (failCount === 0) {
            vscode.window.showInformationMessage(message);
        } else {
            vscode.window.showWarningMessage(message);
        }
    }

    private _sendLoadingStep(step: number, status: 'pending' | 'active' | 'done') {
        this._view?.webview.postMessage({ type: 'loadingStep', step, status });
    }

    private _sendLoadingProgress(text: string) {
        this._view?.webview.postMessage({ type: 'loadingProgress', text });
    }

    private _sendSimpleLoading(text: string) {
        this._view?.webview.postMessage({ type: 'showSimpleLoading', text });
    }

    private _hideLoading() {
        this._view?.webview.postMessage({ type: 'hideLoading' });
    }

    private async _switchAccount(index: number) {
        try {
            const account = this._accounts[index];
            if (!account) {
                this._hideLoading();
                throw new Error('账户不存在');
            }

            // AccessToken 账户特殊处理
            if (account.isAccessToken && account.accessToken) {
                this._sendSimpleLoading('正在切换 AccessToken 账户...');
                
                this._injector.log(`[切换账户] AccessToken 账户: ${account.displayName}`);
                
                // 使用 tokenWriter 写入 accessToken
                const result = await this._tokenWriter.loginWithAccessToken(
                    account.accessToken,
                    account.displayName || 'Token用户'
                );
                
                this._hideLoading();
                
                if (result.success) {
                    this._currentAccountIndex = index;
                    this._saveAccounts();
                    this._updateView();
                    
                    const restart = await vscode.window.showInformationMessage(
                        `已切换到 AccessToken 账户: ${account.displayName}，需要完全退出并重启 Windsurf 才能生效。`,
                        '立即退出',
                        '稍后手动重启'
                    );
                    if (restart === '立即退出') {
                        await vscode.commands.executeCommand('workbench.action.quit');
                    }
                } else {
                    vscode.window.showErrorMessage(`切换失败: ${result.error}`);
                }
                return;
            }

            // 普通账户处理流程
            // 步骤1: 检查 Token 状态
            this._sendLoadingStep(1, 'active');
            this._sendLoadingProgress(`检查 ${account.displayName || account.email} 的 Token...`);
            await this._delay(300);

            // 检查 Token 是否过期
            const tokenExpired = account.expiresAt && Date.now() >= account.expiresAt;
            this._sendLoadingStep(1, 'done');

            // 步骤2: 刷新认证信息
            this._sendLoadingStep(2, 'active');
            if (tokenExpired) {
                this._sendLoadingProgress('Token 已过期，正在刷新...');
                try {
                    await this._refreshToken(index);
                    this._sendLoadingProgress('Token 刷新成功');
                } catch {
                    this._sendLoadingProgress('刷新失败，尝试重新登录...');
                    await this._reLogin(index);
                    this._sendLoadingProgress('重新登录成功');
                }
            } else {
                this._sendLoadingProgress('Token 有效');
                await this._delay(200);
            }
            this._sendLoadingStep(2, 'done');

            // 步骤3: 切换账户
            this._sendLoadingStep(3, 'active');
            this._sendLoadingProgress('正在切换到 Windsurf...');
            
            const result = await this._injector.switchAccount(
                account.idToken || '',
                account.displayName || account.email
            );

            if (!result.success) {
                this._hideLoading();
                throw new Error(result.error || '切换失败');
            }
            this._sendLoadingStep(3, 'done');

            // 步骤4: 完成
            this._sendLoadingStep(4, 'active');
            this._sendLoadingProgress('切换成功！');
            await this._delay(300);
            this._sendLoadingStep(4, 'done');

            this._currentAccountIndex = index;
            this._saveAccounts();
            
            await this._delay(500);
            this._hideLoading();
            this._updateView();
            
            vscode.window.showInformationMessage(`已切换到账户: ${account.displayName || account.email}`);
        } catch (error) {
            this._hideLoading();
            const message = error instanceof Error ? error.message : '切换失败';
            vscode.window.showErrorMessage(`切换账户失败: ${message}`);
        }
    }

    private _delay(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    private async _refreshToken(index: number): Promise<void> {
        const account = this._accounts[index];
        if (!account.refreshToken) {
            throw new Error('没有 refreshToken');
        }

        const response = await fetch(REFRESH_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                grant_type: 'refresh_token',
                refresh_token: account.refreshToken
            })
        });

        if (!response.ok) {
            throw new Error('刷新 Token 失败');
        }

        const data = await response.json() as {
            id_token: string;
            refresh_token: string;
            expires_in: string;
        };

        account.idToken = data.id_token;
        account.refreshToken = data.refresh_token;
        account.expiresAt = Date.now() + (parseInt(data.expires_in) * 1000);
        
        this._saveAccounts();
    }

    private async _reLogin(index: number): Promise<void> {
        const account = this._accounts[index];
        if (!account.password) {
            throw new Error('没有保存密码，请删除后重新添加账户');
        }

        const response = await fetch(AUTH_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                email: account.email, 
                password: account.password, 
                returnSecureToken: true 
            })
        });

        if (!response.ok) {
            const error = await response.json() as { error?: { message?: string } };
            throw new Error(error.error?.message || '重新登录失败');
        }

        const data = await response.json() as {
            idToken: string;
            refreshToken: string;
            expiresIn?: string;
        };

        account.idToken = data.idToken;
        account.refreshToken = data.refreshToken;
        account.expiresAt = Date.now() + (parseInt(data.expiresIn || '3600') * 1000);
        
        this._saveAccounts();
    }

    private async _handleRefreshToken(index: number) {
        try {
            const account = this._accounts[index];
            if (!account) {
                throw new Error('账户不存在');
            }
            
            this._sendSimpleLoading(`正在刷新 ${account.displayName || account.email} 的 Token...`);
            
            try {
                await this._refreshToken(index);
            } catch {
                this._sendSimpleLoading('刷新失败，尝试重新登录...');
                await this._reLogin(index);
            }
            
            this._hideLoading();
            this._updateView();
            vscode.window.showInformationMessage(`账户 ${account.displayName || account.email} Token 刷新成功`);
        } catch (error) {
            this._hideLoading();
            const message = error instanceof Error ? error.message : '刷新失败';
            vscode.window.showErrorMessage(`刷新 Token 失败: ${message}`);
        }
    }

    private async _refreshUsage() {
        if (this._currentAccountIndex >= 0) {
            await this._refreshAccountUsage(this._currentAccountIndex);
        } else {
            vscode.window.showWarningMessage('请先切换到一个账户');
        }
    }

    private async _refreshAccountUsage(index: number) {
        try {
            const account = this._accounts[index];
            if (!account || !account.idToken) {
                vscode.window.showWarningMessage('账户 Token 不存在，请刷新 Token');
                return;
            }

            this._sendSimpleLoading(`正在查询 ${account.displayName || account.email} 的用量...`);

            // 检查 Token 是否过期
            if (account.expiresAt && Date.now() >= account.expiresAt) {
                this._sendSimpleLoading('Token 已过期，正在刷新...');
                await this._refreshToken(index);
            }

            this._sendSimpleLoading('正在获取用量信息...');
            let usageInfo = await this._injector.getUsage(account.idToken!);
            
            // 如果刷新失败，尝试重新登录再试
            if (!usageInfo) {
                this._sendSimpleLoading('用量查询失败，尝试重新登录...');
                try {
                    await this._reLogin(index);
                    this._sendSimpleLoading('重新登录成功，再次查询用量...');
                    usageInfo = await this._injector.getUsage(this._accounts[index].idToken!);
                } catch (reloginError) {
                    this._injector.log(`[用量查询] ✗ ${account.email} - 重新登录失败`);
                }
            }

            if (usageInfo) {
                account.usageInfo = usageInfo;
                this._saveAccounts();
                this._hideLoading();
                this._updateView();
                vscode.window.showInformationMessage(
                    `${account.displayName || account.email}: ${usageInfo.userPromptCredits.left}/${usageInfo.userPromptCredits.total} credits`
                );
            } else {
                this._hideLoading();
            }
        } catch (error) {
            this._hideLoading();
            const message = error instanceof Error ? error.message : '查询失败';
            vscode.window.showErrorMessage(`查询用量失败: ${message}`);
        }
    }

    private async _refreshAllUsage() {
        if (this._accounts.length === 0) {
            vscode.window.showWarningMessage('没有账户，请先添加账户');
            return;
        }

        // 过滤掉 accessToken 账户
        const normalAccounts = this._accounts.filter(a => !a.isAccessToken);
        const skippedCount = this._accounts.length - normalAccounts.length;

        if (normalAccounts.length === 0) {
            vscode.window.showWarningMessage('没有可刷新的账户（AccessToken 账户不支持刷新）');
            return;
        }

        let successCount = 0;
        let failCount = 0;
        let deleteCount = 0;
        const total = normalAccounts.length;
        const accountsToDelete: number[] = [];

        this._injector.log(`[一键刷新] 开始处理 ${total} 个账户 (跳过 ${skippedCount} 个 SK 账户)`);
        this._sendSimpleLoading(`正在刷新所有账户用量 (0/${total})...`);

        for (let i = 0; i < this._accounts.length; i++) {
            const account = this._accounts[i];
            
            // 跳过 accessToken 账户
            if (account.isAccessToken) {
                continue;
            }
            
            this._sendSimpleLoading(`正在查询 ${account.displayName || account.email} (${successCount + failCount + 1}/${total})...`);

            try {
                // 检查 Token 是否过期
                if (account.expiresAt && Date.now() >= account.expiresAt) {
                    this._injector.log(`[一键刷新] ${account.email} - Token 已过期`);
                    try {
                        await this._refreshToken(i);
                    } catch (refreshError) {
                        this._injector.log(`[一键刷新] ${account.email} - refreshToken 失败，尝试重新登录`);
                        try {
                            await this._reLogin(i);
                        } catch (reloginError) {
                            this._injector.log(`[一键刷新] ✗ ${account.email} - 重新登录失败`);
                            throw reloginError;
                        }
                    }
                }

                let usageInfo = await this._injector.getUsage(this._accounts[i].idToken!);
                
                // 如果用量查询失败，尝试重新登录再试
                if (!usageInfo) {
                    this._injector.log(`[一键刷新] ${account.email} - 用量查询失败，尝试重新登录`);
                    try {
                        await this._reLogin(i);
                        usageInfo = await this._injector.getUsage(this._accounts[i].idToken!);
                    } catch (reloginError) {
                        this._injector.log(`[一键刷新] ✗ ${account.email} - 重新登录失败`);
                    }
                }

                if (usageInfo) {
                    this._accounts[i].usageInfo = usageInfo;
                    this._injector.log(`[一键刷新] ✓ ${account.email} - ${usageInfo.userPromptCredits.left}/${usageInfo.userPromptCredits.total} credits`);
                    
                    // 检查用量是否为0，标记删除
                    if (usageInfo.userPromptCredits.left <= 0) {
                        accountsToDelete.push(i);
                        this._injector.log(`[一键刷新] 🗑 ${account.email} - 用量为0，标记删除`);
                        deleteCount++;
                    }
                    successCount++;
                } else {
                    this._injector.log(`[一键刷新] ✗ ${account.email} - 查询失败`);
                    failCount++;
                }
            } catch (error) {
                const message = error instanceof Error ? error.message : '未知错误';
                this._injector.log(`[一键刷新] ✗ ${account.email} - ${message}`);
                failCount++;
            }
        }

        // 从后往前删除，避免索引变化
        for (let i = accountsToDelete.length - 1; i >= 0; i--) {
            const index = accountsToDelete[i];
            const deletedAccount = this._accounts[index];
            this._accounts.splice(index, 1);
            this._injector.log(`[一键刷新] 🗑 已删除 ${deletedAccount.email}`);
            
            // 如果删除的是当前账户，重置索引
            if (index === this._currentAccountIndex) {
                this._currentAccountIndex = -1;
            } else if (index < this._currentAccountIndex) {
                this._currentAccountIndex--;
            }
        }

        this._injector.log(`[一键刷新] 完成 - 成功 ${successCount} | 失败 ${failCount} | 删除 ${deleteCount}`);
        this._saveAccounts();
        this._hideLoading();
        this._updateView();

        const message = `用量刷新完成：成功 ${successCount} 个${deleteCount > 0 ? `，删除 ${deleteCount} 个用量为0的账户` : ''}${failCount > 0 ? `，失败 ${failCount} 个（查看日志）` : ''}`;
        if (failCount === 0) {
            vscode.window.showInformationMessage(message);
        } else {
            vscode.window.showWarningMessage(message);
        }
    }

    private async _loginWithToken(token: string, name?: string) {
        try {
            if (!token || !token.trim()) {
                vscode.window.showWarningMessage('请输入有效的 Token');
                return;
            }

            this._sendSimpleLoading('正在登录 Windsurf...');
            
            const trimmedToken = token.trim();
            const displayName = name?.trim() || 'Token用户';
            
            // 检查是否是 accessToken (sk-ws-01-xxx 格式)
            const isAccessToken = trimmedToken.startsWith('sk-ws-');
            
            this._injector.log(`[Token登录] 开始登录: ${displayName}, 类型: ${isAccessToken ? 'accessToken' : 'idToken'}`);
            
            if (isAccessToken) {
                // accessToken 格式，写入数据库
                this._sendSimpleLoading('正在写入登录信息...');
                const result = await this._tokenWriter.loginWithAccessToken(trimmedToken, displayName);
                
                this._hideLoading();
                
                if (result.success) {
                    const restart = await vscode.window.showInformationMessage(
                        `登录信息已写入！需要重启 Windsurf 才能生效。`,
                        '立即重启',
                        '稍后重启'
                    );
                    if (restart === '立即重启') {
                        await vscode.commands.executeCommand('workbench.action.reloadWindow');
                    }
                } else {
                    vscode.window.showErrorMessage(`登录失败: ${result.error}`);
                }
            } else {
                // idToken 格式，使用原有方式
                const result = await this._injector.switchAccount(trimmedToken, displayName);
                
                this._hideLoading();
                
                if (result.success) {
                    vscode.window.showInformationMessage(`登录成功: ${displayName}`);
                } else {
                    vscode.window.showErrorMessage(`登录失败: ${result.error}`);
                }
            }
        } catch (error) {
            this._hideLoading();
            const message = error instanceof Error ? error.message : 'Token 登录失败';
            this._injector.log(`[Token登录] ✗ 失败: ${message}`);
            vscode.window.showErrorMessage(`Token 登录失败: ${message}`);
        }
    }

    private async _addAccessTokenAccount(token: string, name?: string) {
        try {
            if (!token || !token.trim()) {
                vscode.window.showWarningMessage('请输入有效的 AccessToken');
                return;
            }

            const trimmedToken = token.trim();
            
            // 验证是否是 sk-ws-xxx 格式
            if (!trimmedToken.startsWith('sk-ws-')) {
                vscode.window.showWarningMessage('AccessToken 格式不正确，应以 sk-ws- 开头');
                return;
            }

            // 检查是否已存在相同的 accessToken
            const existingIndex = this._accounts.findIndex(a => a.accessToken === trimmedToken);
            if (existingIndex >= 0) {
                vscode.window.showWarningMessage('该 AccessToken 已存在');
                return;
            }

            this._sendSimpleLoading('正在添加 AccessToken 账户...');

            const displayName = name?.trim() || `Token-${trimmedToken.slice(-6)}`;
            const tokenId = `sk-${Date.now()}`;

            const account: Account = {
                email: `accesstoken-${tokenId}@local`,
                password: '',
                displayName: displayName,
                localId: tokenId,
                accessToken: trimmedToken,
                isAccessToken: true
            };

            this._accounts.push(account);
            this._saveAccounts();
            
            this._hideLoading();
            this._updateView();
            
            this._injector.log(`[添加AccessToken] ✓ ${displayName}`);
            vscode.window.showInformationMessage(`AccessToken 账户 ${displayName} 添加成功`);
        } catch (error) {
            this._hideLoading();
            const message = error instanceof Error ? error.message : '添加失败';
            this._injector.log(`[添加AccessToken] ✗ 失败: ${message}`);
            vscode.window.showErrorMessage(`添加 AccessToken 账户失败: ${message}`);
        }
    }

    private _openAccountsFolder() {
        const folderPath = this._context.globalStorageUri.fsPath;
        // 确保目录存在
        if (!fs.existsSync(folderPath)) {
            fs.mkdirSync(folderPath, { recursive: true });
        }
        // 使用 vscode.commands 打开文件夹
        vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(folderPath));
        this._injector.log(`[打开目录] ✓ ${folderPath}`);
    }

    private async _handleGetLocalToken() {
        try {
            this._sendSimpleLoading('正在读取本地账户信息...');
            
            const result = await this._tokenReader.getLocalToken();
            
            if (result.error) {
                this._hideLoading();
                this._localToken = null;
                this._view?.webview.postMessage({ 
                    type: 'localTokenResult', 
                    success: false, 
                    error: result.error,
                    accountName: result.accountName 
                });
                vscode.window.showErrorMessage(`获取本地 Token 失败: ${result.error}`);
                return;
            }

            if (result.session) {
                this._localToken = result.session.accessToken;
                this._hideLoading();
                this._view?.webview.postMessage({ 
                    type: 'localTokenResult', 
                    success: true, 
                    accountName: result.accountName,
                    token: result.session.accessToken
                });
                vscode.window.showInformationMessage(`成功获取 ${result.accountName} 的 accessToken`);
            }
        } catch (error) {
            this._hideLoading();
            const message = error instanceof Error ? error.message : '获取失败';
            vscode.window.showErrorMessage(`获取本地 Token 失败: ${message}`);
        }
    }

    private async _copyLocalToken() {
        if (this._localToken) {
            await vscode.env.clipboard.writeText(this._localToken);
            vscode.window.showInformationMessage('Token 已复制到剪贴板');
        } else {
            vscode.window.showWarningMessage('请先获取本地 Token');
        }
    }

    private async _useLocalToken() {
        if (!this._localToken) {
            vscode.window.showWarningMessage('请先获取本地 Token');
            return;
        }

        try {
            this._sendSimpleLoading('正在使用本地 Token 切换账户...');
            
            // 本地获取的是 accessToken (sk-ws-01-xxx 格式)，可以直接用于切换
            // 注意：accessToken 不同于 idToken，无法用于 getUsage API
            const result = await this._injector.switchAccount(this._localToken, '本地账户');
            
            if (result.success) {
                this._hideLoading();
                vscode.window.showInformationMessage('切换成功！请重启 Windsurf 以生效');
            } else {
                this._hideLoading();
                vscode.window.showErrorMessage(`切换失败: ${result.error}`);
            }
        } catch (error) {
            this._hideLoading();
            const message = error instanceof Error ? error.message : '切换失败';
            vscode.window.showErrorMessage(`使用本地 Token 失败: ${message}`);
        }
    }

    private _migrateOldData() {
        try {
            const newPath = this._context.globalStorageUri.fsPath;
            const parentPath = path.dirname(newPath);
            
            // 查找旧的 undefined_publisher 目录
            if (fs.existsSync(parentPath)) {
                const oldDirs = fs.readdirSync(parentPath).filter(dir => 
                    dir.includes('undefined_publisher') && dir.includes('windsurf-login')
                );
                
                if (oldDirs.length > 0) {
                    const oldPath = path.join(parentPath, oldDirs[0]);
                    const oldAccountsFile = path.join(oldPath, 'accounts.json');
                    const newAccountsFile = this._accountsFilePath;
                    
                    // 如果旧文件存在且新文件不存在，则迁移
                    if (fs.existsSync(oldAccountsFile) && !fs.existsSync(newAccountsFile)) {
                        this._injector.log(`[数据迁移] 开始迁移数据`);
                        
                        // 复制文件
                        const data = fs.readFileSync(oldAccountsFile, 'utf-8');
                        fs.writeFileSync(newAccountsFile, data, 'utf-8');
                        
                        this._injector.log(`[数据迁移] ✓ 迁移成功`);
                        vscode.window.showInformationMessage('账户数据已自动迁移到新位置');
                    }
                }
            }
        } catch (error) {
            this._injector.log(`[数据迁移] ✗ 失败: ${error instanceof Error ? error.message : '未知错误'}`);
        }
    }

    private async _handleResetMachineId() {
        try {
            const confirm = await vscode.window.showWarningMessage(
                '确定要重置 Windsurf 机器码吗？重置后将自动重启 Windsurf。',
                { modal: true },
                '确定并重启',
                '取消'
            );

            if (confirm !== '确定并重启') {
                return;
            }

            this._sendSimpleLoading('正在重置机器码...');

            const result = await this._resetter.resetMachineId();
            
            if (result.success) {
                this._sendSimpleLoading('重置成功，即将重启...');
                vscode.window.showInformationMessage(
                    `机器码重置成功！新机器码: ${result.newMachineId}\nWindsurf 将在 3 秒后自动重启...`
                );

                // 3 秒后自动重启
                setTimeout(async () => {
                    await vscode.commands.executeCommand('workbench.action.reloadWindow');
                }, 3000);
            } else {
                throw new Error(result.error || '重置失败');
            }
        } catch (error) {
            this._hideLoading();
            const message = error instanceof Error ? error.message : '重置失败';
            vscode.window.showErrorMessage(`重置机器码失败: ${message}`);
        }
    }

    private _updateView() {
        if (this._view) {
            this._view.webview.html = this._getHtmlForWebview();
        }
    }

    private _getHtmlForWebview(): string {
        const usageHtml = this._usageInfo ? `
            <div class="usage-card">
                <div class="usage-header">
                    <span class="usage-title">用量信息</span>
                    <span class="plan-badge">${this._usageInfo.planName}</span>
                </div>
                <div class="usage-item">
                    <span class="usage-label">User Prompt Credits</span>
                    <div class="usage-bar-container">
                        <div class="usage-bar" style="width: ${Math.min(100, (this._usageInfo.userPromptCredits.used / this._usageInfo.userPromptCredits.total) * 100)}%"></div>
                    </div>
                    <span class="usage-value">${this._usageInfo.userPromptCredits.used.toFixed(2)} / ${this._usageInfo.userPromptCredits.total} used</span>
                    <span class="usage-left">${this._usageInfo.userPromptCredits.left.toFixed(2)} left</span>
                </div>
                <div class="usage-item">
                    <span class="usage-label">Add-on Credits</span>
                    <span class="usage-value">${this._usageInfo.addOnCredits.left.toFixed(2)} left</span>
                </div>
            </div>
        ` : '';

        const accountsHtml = this._accounts.length > 0
            ? this._accounts.map((acc, i) => {
                const isCurrent = i === this._currentAccountIndex;
                const currentBadge = isCurrent ? '<span class="current-badge">当前</span>' : '';
                const accessTokenBadge = acc.isAccessToken ? '<span class="access-token-badge">SK</span>' : '';
                const usage = acc.usageInfo;
                const expiresText = usage?.expiresAt 
                    ? `<span class="remaining-days">${new Date(usage.expiresAt).toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' }).replace(/\//g, '-')}</span>` 
                    : '';
                const usageHtml = usage ? `
                    <div class="account-usage">
                        <span class="plan-badge-small">${usage.planName}</span>
                        <span class="usage-text">${usage.userPromptCredits.left}/${usage.userPromptCredits.total}</span>
                        ${expiresText}
                    </div>
                ` : '';
                const emailDisplay = acc.isAccessToken 
                    ? `<span class="account-email">sk-ws-...${acc.accessToken?.slice(-8) || ''}</span>`
                    : `<span class="account-email">${acc.email}</span>`;
                return `
                <div class="account-item ${isCurrent ? 'current' : ''} ${acc.isAccessToken ? 'access-token-account' : ''}">
                    <div class="account-info">
                        <span class="account-name">${acc.displayName || '未知用户'} ${accessTokenBadge} ${currentBadge}</span>
                        ${emailDisplay}
                        ${usageHtml}
                    </div>
                    <div class="account-actions">
                        ${acc.isAccessToken ? '' : `<button class="action-btn refresh-btn" onclick="refreshToken(${i})">刷新</button>`}
                        <button class="action-btn switch-btn" onclick="switchAccount(${i})" ${isCurrent ? 'disabled' : ''}>切换</button>
                        <button class="action-btn delete-btn" onclick="deleteAccount(${i})">删除</button>
                    </div>
                </div>
            `}).join('')
            : '<div class="no-accounts">暂无账户</div>';

        return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
    <title>Windsurf Login</title>
    <style>
        body { padding: 10px; font-family: var(--vscode-font-family); color: var(--vscode-foreground); }
        .status-bar { 
            display: flex; justify-content: space-between; align-items: center;
            padding: 8px; margin-bottom: 10px; 
            background: var(--vscode-editor-inactiveSelectionBackground); 
            border-radius: 4px; font-size: 12px;
        }
        .add-btn { 
            width: 100%; padding: 8px; 
            background: var(--vscode-button-background); 
            color: var(--vscode-button-foreground); 
            border: none; border-radius: 2px; cursor: pointer; margin-bottom: 15px; 
        }
        .add-btn:hover { background: var(--vscode-button-hoverBackground); }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 100; }
        .modal.show { display: flex; align-items: center; justify-content: center; }
        .modal-content { 
            background: var(--vscode-editor-background); 
            padding: 20px; border-radius: 4px; width: 90%; max-width: 300px; 
        }
        .form-group { margin-bottom: 12px; }
        label { display: block; margin-bottom: 5px; font-size: 12px; }
        input { 
            width: 100%; padding: 8px; box-sizing: border-box; 
            background: var(--vscode-input-background); 
            color: var(--vscode-input-foreground); 
            border: 1px solid var(--vscode-input-border); border-radius: 2px; 
        }
        .modal-buttons { display: flex; gap: 10px; margin-top: 15px; }
        .modal-buttons button { flex: 1; padding: 8px; border: none; border-radius: 2px; cursor: pointer; }
        .btn-confirm { background: var(--vscode-button-background); color: var(--vscode-button-foreground); }
        .btn-cancel { background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground); }
        .accounts-list { margin-top: 10px; }
        .account-item { 
            display: flex; justify-content: space-between; align-items: center; 
            padding: 10px 12px; background: var(--vscode-list-hoverBackground); 
            border-radius: 4px; margin-bottom: 8px; border: 1px solid transparent;
            transition: all 0.2s;
        }
        .account-item:hover {
            background: var(--vscode-list-activeSelectionBackground);
            border-color: var(--vscode-focusBorder);
        }
        .account-item.current { 
            border-left: 3px solid var(--vscode-button-background); 
            background: var(--vscode-list-inactiveSelectionBackground); 
        }
        .account-info { 
            display: flex; flex-direction: column; overflow: hidden; flex: 1; 
            margin-right: 12px; min-width: 0;
        }
        .account-name { 
            font-size: 13px; font-weight: 600; display: flex; align-items: center; gap: 6px; 
            white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
        }
        .account-email { 
            font-size: 11px; color: var(--vscode-descriptionForeground); 
            overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-top: 2px;
        }
        .current-badge { 
            font-size: 10px; padding: 2px 6px; 
            background: var(--vscode-button-background); 
            color: var(--vscode-button-foreground); 
            border-radius: 10px; font-weight: normal; flex-shrink: 0;
        }
        .access-token-badge {
            font-size: 9px; padding: 2px 5px;
            background: #d97706;
            color: white;
            border-radius: 3px; font-weight: 600; flex-shrink: 0;
        }
        .access-token-account {
            border-left: 3px solid #d97706 !important;
        }
        .account-actions { 
            display: flex; gap: 6px; align-items: center; flex-shrink: 0; 
        }
        .action-btn { 
            padding: 4px 10px; height: 26px; 
            background: var(--vscode-button-secondaryBackground); 
            color: var(--vscode-button-secondaryForeground); 
            border: none; border-radius: 4px; cursor: pointer; 
            font-size: 12px; transition: all 0.2s ease;
            white-space: nowrap;
        }
        .action-btn:hover { 
            background: var(--vscode-button-hoverBackground); 
            color: var(--vscode-button-foreground);
        }
        .switch-btn { background: var(--vscode-button-background); color: var(--vscode-button-foreground); }
        .delete-btn:hover { background: #c42b1c; color: white; }
        .account-usage {
            display: flex; align-items: center; gap: 6px; margin-top: 3px;
        }
        .plan-badge-small {
            font-size: 9px; padding: 1px 4px;
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border-radius: 2px;
        }
        .usage-text {
            font-size: 11px; color: var(--vscode-descriptionForeground);
        }
        .remaining-days {
            font-size: 10px; padding: 1px 4px;
            background: var(--vscode-editorWarning-foreground);
            color: var(--vscode-editor-background);
            border-radius: 2px; font-weight: 500;
        }
        .action-btn:disabled { opacity: 0.4; cursor: not-allowed; transform: none; }
        .no-accounts { text-align: center; color: var(--vscode-descriptionForeground); padding: 20px; font-size: 12px; }
        /* 加载遮罩层样式 */
        .loading-overlay {
            display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.7); z-index: 200;
            flex-direction: column; align-items: center; justify-content: center;
        }
        .loading-overlay.show { display: flex; }
        .loading-spinner {
            width: 40px; height: 40px; border: 3px solid var(--vscode-button-secondaryBackground);
            border-top-color: var(--vscode-button-background); border-radius: 50%;
            animation: spin 1s linear infinite; margin-bottom: 15px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .loading-text { color: var(--vscode-foreground); font-size: 14px; margin-bottom: 8px; }
        .loading-progress { color: var(--vscode-descriptionForeground); font-size: 12px; }
        .loading-steps {
            margin-top: 15px; text-align: left; font-size: 11px;
            color: var(--vscode-descriptionForeground); max-width: 200px;
        }
        .loading-step { padding: 4px 0; display: flex; align-items: center; gap: 8px; }
        .loading-step.done { color: var(--vscode-testing-iconPassed, #89d185); }
        .loading-step.active { color: var(--vscode-foreground); }
        .loading-step.pending { opacity: 0.5; }
        .step-icon { width: 14px; text-align: center; }
        .section-title { font-size: 11px; text-transform: uppercase; color: var(--vscode-descriptionForeground); margin-bottom: 8px; }
        .usage-card { 
            background: var(--vscode-editor-inactiveSelectionBackground); 
            border-radius: 4px; padding: 10px; margin-bottom: 15px; 
        }
        .usage-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .usage-title { font-size: 12px; font-weight: 500; }
        .plan-badge { 
            font-size: 10px; padding: 2px 6px; 
            background: var(--vscode-button-background); 
            color: var(--vscode-button-foreground); 
            border-radius: 2px; 
        }
        .usage-item { margin-bottom: 8px; }
        .usage-label { font-size: 11px; color: var(--vscode-descriptionForeground); display: block; margin-bottom: 4px; }
        .usage-bar-container { 
            height: 6px; background: var(--vscode-input-background); 
            border-radius: 3px; overflow: hidden; margin-bottom: 4px; 
        }
        .usage-bar { height: 100%; background: var(--vscode-button-background); border-radius: 3px; }
        .usage-value { font-size: 12px; }
        .usage-left { font-size: 11px; color: var(--vscode-descriptionForeground); margin-left: 8px; }
    </style>
</head>
<body>
    <div class="status-bar">
        <span>Windsurf 账户管理</span>
        <div style="display: flex; gap: 4px;">
            <button onclick="showLog()" style="padding: 2px 6px; font-size: 10px; background: transparent; border: 1px solid var(--vscode-button-secondaryBackground); color: var(--vscode-foreground); border-radius: 2px; cursor: pointer;">日志</button>
            <button onclick="openAccountsFolder()" style="padding: 2px 6px; font-size: 10px; background: transparent; border: 1px solid var(--vscode-button-secondaryBackground); color: var(--vscode-foreground); border-radius: 2px; cursor: pointer;">账户</button>
        </div>
    </div>

    <div style="display: flex; gap: 8px; margin-bottom: 10px;">
        <button class="add-btn" onclick="showModal()" style="flex: 1; margin-bottom: 0;">+ 添加账户</button>
        <button class="add-btn" onclick="showBatchModal()" style="flex: 1; margin-bottom: 0; background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground);">+ 批量添加</button>
    </div>
    
    <div style="display: flex; gap: 8px; margin-bottom: 10px;">
        <button class="add-btn" onclick="showAccessTokenModal()" style="flex: 1; margin-bottom: 0; background: #d97706; color: white;">🔑 添加 AccessToken</button>
    </div>
    
    <div style="display: flex; gap: 8px; margin-bottom: 10px;">
        <button class="add-btn" onclick="showTokenModal()" style="flex: 1; margin-bottom: 0; background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground);">🔑 Token 登录</button>
        <button class="add-btn" onclick="getLocalToken()" style="flex: 1; margin-bottom: 0; background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground);">📥 获取本地Token</button>
    </div>
    
    <!-- 本地 Token 显示区域 -->
    <div id="localTokenArea" style="display: none; margin-bottom: 10px; padding: 10px; background: var(--vscode-editor-inactiveSelectionBackground); border-radius: 4px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <span style="font-size: 12px; font-weight: 500;">本地账户 Token</span>
            <span id="localAccountName" style="font-size: 11px; color: var(--vscode-descriptionForeground);"></span>
        </div>
        <div style="background: var(--vscode-input-background); padding: 8px; border-radius: 2px; margin-bottom: 8px; max-height: 60px; overflow: auto;">
            <code id="localTokenDisplay" style="font-size: 10px; word-break: break-all; color: var(--vscode-input-foreground);"></code>
        </div>
        <div style="display: flex; gap: 8px;">
            <button class="add-btn" onclick="copyLocalToken()" style="flex: 1; margin-bottom: 0; font-size: 11px; padding: 6px;">📋 复制</button>
            <button class="add-btn" onclick="useLocalToken()" style="flex: 1; margin-bottom: 0; font-size: 11px; padding: 6px;">🚀 使用此Token切换</button>
        </div>
    </div>
    
    <div style="display: flex; gap: 8px; margin-bottom: 10px;">
        <button class="add-btn" onclick="resetMachineId()" style="flex: 1; margin-bottom: 0; background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground);">🔄 重置机器码</button>
        <button class="add-btn" onclick="refreshAllUsage()" style="flex: 1; margin-bottom: 0; background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground);">📊 一键刷新用量</button>
    </div>
    
    ${usageHtml}
    
    <div class="section-title">已添加的账户</div>
    <div class="accounts-list">${accountsHtml}</div>

    <!-- 加载遮罩层 -->
    <div class="loading-overlay" id="loadingOverlay">
        <div class="loading-spinner"></div>
        <div class="loading-text" id="loadingText">正在登录...</div>
        <div class="loading-progress" id="loadingProgress"></div>
        <div class="loading-steps" id="loadingSteps">
            <div class="loading-step pending" id="step1"><span class="step-icon">○</span>检查 Token 状态</div>
            <div class="loading-step pending" id="step2"><span class="step-icon">○</span>刷新认证信息</div>
            <div class="loading-step pending" id="step3"><span class="step-icon">○</span>切换账户</div>
            <div class="loading-step pending" id="step4"><span class="step-icon">○</span>完成</div>
        </div>
    </div>

    <div class="modal" id="modal">
        <div class="modal-content">
            <div class="form-group">
                <label>邮箱</label>
                <input type="email" id="email" placeholder="请输入邮箱">
            </div>
            <div class="form-group">
                <label>密码</label>
                <input type="password" id="password" placeholder="请输入密码">
            </div>
            <div class="modal-buttons">
                <button class="btn-cancel" onclick="hideModal()">取消</button>
                <button class="btn-confirm" onclick="addAccount()">确定</button>
            </div>
        </div>
    </div>

    <div class="modal" id="batchModal">
        <div class="modal-content" style="max-width: 400px;">
            <div class="form-group">
                <label>批量添加账户（每行一个，格式: 邮箱----密码）</label>
                <textarea id="batchAccounts" placeholder="example1@email.com----password1&#10;example2@email.com----password2" style="width: 100%; height: 150px; padding: 8px; box-sizing: border-box; background: var(--vscode-input-background); color: var(--vscode-input-foreground); border: 1px solid var(--vscode-input-border); border-radius: 2px; resize: vertical; font-family: monospace; font-size: 12px;"></textarea>
            </div>
            <div class="modal-buttons">
                <button class="btn-cancel" onclick="hideBatchModal()">取消</button>
                <button class="btn-confirm" onclick="batchAddAccounts()">批量添加</button>
            </div>
        </div>
    </div>

    <!-- Token 登录弹窗 -->
    <div class="modal" id="tokenModal">
        <div class="modal-content" style="max-width: 400px;">
            <div class="form-group">
                <label>账户名称（可选）</label>
                <input type="text" id="tokenName" placeholder="用于显示的账户名称">
            </div>
            <div class="form-group">
                <label>Token</label>
                <textarea id="tokenInput" placeholder="请输入 idToken" style="width: 100%; height: 120px; padding: 8px; box-sizing: border-box; background: var(--vscode-input-background); color: var(--vscode-input-foreground); border: 1px solid var(--vscode-input-border); border-radius: 2px; resize: vertical; font-family: monospace; font-size: 11px;"></textarea>
            </div>
            <div class="modal-buttons">
                <button class="btn-cancel" onclick="hideTokenModal()">取消</button>
                <button class="btn-confirm" onclick="loginWithToken()">登录</button>
            </div>
        </div>
    </div>

    <!-- AccessToken 添加弹窗 -->
    <div class="modal" id="accessTokenModal">
        <div class="modal-content" style="max-width: 400px;">
            <div class="form-group">
                <label>账户名称（可选）</label>
                <input type="text" id="accessTokenName" placeholder="用于显示的账户名称">
            </div>
            <div class="form-group">
                <label>AccessToken (sk-ws-xxx 格式)</label>
                <textarea id="accessTokenInput" placeholder="请输入 sk-ws-xxx 格式的 AccessToken" style="width: 100%; height: 100px; padding: 8px; box-sizing: border-box; background: var(--vscode-input-background); color: var(--vscode-input-foreground); border: 1px solid var(--vscode-input-border); border-radius: 2px; resize: vertical; font-family: monospace; font-size: 11px;"></textarea>
            </div>
            <div style="font-size: 11px; color: var(--vscode-descriptionForeground); margin-bottom: 10px;">
                提示: AccessToken 账户将单独标记，不支持刷新 Token 和用量查询
            </div>
            <div class="modal-buttons">
                <button class="btn-cancel" onclick="hideAccessTokenModal()">取消</button>
                <button class="btn-confirm" style="background: #d97706;" onclick="addAccessTokenAccount()">添加</button>
            </div>
        </div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        function showModal() { document.getElementById('modal').classList.add('show'); }
        function hideModal() { 
            document.getElementById('modal').classList.remove('show'); 
            document.getElementById('email').value = ''; 
            document.getElementById('password').value = ''; 
        }
        function showBatchModal() { document.getElementById('batchModal').classList.add('show'); }
        function hideBatchModal() { 
            document.getElementById('batchModal').classList.remove('show'); 
            document.getElementById('batchAccounts').value = ''; 
        }
        function showTokenModal() { document.getElementById('tokenModal').classList.add('show'); }
        function hideTokenModal() { 
            document.getElementById('tokenModal').classList.remove('show'); 
            document.getElementById('tokenName').value = ''; 
            document.getElementById('tokenInput').value = ''; 
        }
        function showAccessTokenModal() { document.getElementById('accessTokenModal').classList.add('show'); }
        function hideAccessTokenModal() { 
            document.getElementById('accessTokenModal').classList.remove('show'); 
            document.getElementById('accessTokenName').value = ''; 
            document.getElementById('accessTokenInput').value = ''; 
        }
        function addAccessTokenAccount() {
            const token = document.getElementById('accessTokenInput').value;
            const name = document.getElementById('accessTokenName').value;
            if (token && token.trim()) {
                hideAccessTokenModal();
                vscode.postMessage({ type: 'addAccessTokenAccount', token: token.trim(), name: name.trim() || undefined });
            }
        }
        function loginWithToken() {
            const token = document.getElementById('tokenInput').value;
            const name = document.getElementById('tokenName').value;
            if (token && token.trim()) {
                hideTokenModal();
                vscode.postMessage({ type: 'loginWithToken', token: token.trim(), name: name.trim() || undefined });
            }
        }
        function batchAddAccounts() {
            const text = document.getElementById('batchAccounts').value.trim();
            if (!text) return;
            const lines = text.split('\\n').filter(line => line.trim());
            const accounts = [];
            for (const line of lines) {
                const parts = line.split('----');
                if (parts.length >= 2) {
                    accounts.push({ email: parts[0].trim(), password: parts[1].trim() });
                }
            }
            if (accounts.length > 0) {
                hideBatchModal();
                vscode.postMessage({ type: 'batchAddAccounts', accounts });
            }
        }
        function addAccount() {
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            if (email && password) {
                vscode.postMessage({ type: 'addAccount', email, password });
                hideModal();
            }
        }
        function deleteAccount(index) { 
            vscode.postMessage({ type: 'deleteAccount', index }); 
        }
        function switchAccount(index) {
            showStepsLoading('正在切换账户...');
            vscode.postMessage({ type: 'switchAccount', index }); 
        }
        function showLoading(text) {
            document.getElementById('loadingText').textContent = text || '正在处理...';
            document.getElementById('loadingProgress').textContent = '';
            document.getElementById('loadingSteps').style.display = 'block';
            resetLoadingSteps();
            document.getElementById('loadingOverlay').classList.add('show');
        }
        function hideLoading() {
            document.getElementById('loadingOverlay').classList.remove('show');
        }
        function updateLoadingProgress(text) {
            document.getElementById('loadingProgress').textContent = text;
        }
        function resetLoadingSteps() {
            for (let i = 1; i <= 4; i++) {
                const step = document.getElementById('step' + i);
                step.className = 'loading-step pending';
                step.querySelector('.step-icon').textContent = '○';
            }
        }
        function updateLoadingStep(stepNum, status) {
            const step = document.getElementById('step' + stepNum);
            if (!step) return;
            step.className = 'loading-step ' + status;
            if (status === 'done') {
                step.querySelector('.step-icon').textContent = '✓';
            } else if (status === 'active') {
                step.querySelector('.step-icon').textContent = '◉';
            } else {
                step.querySelector('.step-icon').textContent = '○';
            }
        }
        function showSimpleLoading(text) {
            document.getElementById('loadingText').textContent = text || '正在处理...';
            document.getElementById('loadingProgress').textContent = '';
            document.getElementById('loadingSteps').style.display = 'none';
            document.getElementById('loadingOverlay').classList.add('show');
        }
        function showStepsLoading(text) {
            document.getElementById('loadingText').textContent = text || '正在处理...';
            document.getElementById('loadingProgress').textContent = '';
            document.getElementById('loadingSteps').style.display = 'block';
            resetLoadingSteps();
            document.getElementById('loadingOverlay').classList.add('show');
        }
        // 监听来自扩展的消息
        window.addEventListener('message', event => {
            const message = event.data;
            switch (message.type) {
                case 'showSimpleLoading':
                    showSimpleLoading(message.text);
                    break;
                case 'loadingProgress':
                    updateLoadingProgress(message.text);
                    break;
                case 'loadingStep':
                    updateLoadingStep(message.step, message.status);
                    break;
                case 'hideLoading':
                    hideLoading();
                    break;
                case 'localTokenResult':
                    if (message.success) {
                        showLocalToken(message.accountName, message.token);
                    } else {
                        hideLocalToken();
                    }
                    break;
            }
        });
        function showLog() { 
            vscode.postMessage({ type: 'showLog' }); 
        }
        function refreshToken(index) { 
            vscode.postMessage({ type: 'refreshToken', index }); 
        }
        function refreshUsage() { 
            vscode.postMessage({ type: 'refreshUsage' }); 
        }
        function resetMachineId() { 
            vscode.postMessage({ type: 'resetMachineId' }); 
        }
        function refreshAllUsage() {
            vscode.postMessage({ type: 'refreshAllUsage' });
        }
        function openAccountsFolder() {
            vscode.postMessage({ type: 'openAccountsFolder' });
        }
        function getLocalToken() {
            vscode.postMessage({ type: 'getLocalToken' });
        }
        function copyLocalToken() {
            vscode.postMessage({ type: 'copyLocalToken' });
        }
        function useLocalToken() {
            vscode.postMessage({ type: 'useLocalToken' });
        }
        function showLocalToken(accountName, token) {
            document.getElementById('localAccountName').textContent = accountName;
            document.getElementById('localTokenDisplay').textContent = token;
            document.getElementById('localTokenArea').style.display = 'block';
        }
        function hideLocalToken() {
            document.getElementById('localTokenArea').style.display = 'none';
        }
        function addAccountWithLoading() {
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            if (email && password) {
                hideModal();
                showLoading('正在添加账户...');
                vscode.postMessage({ type: 'addAccount', email, password });
            }
        }
    </script>
</body>
</html>`;
    }
}
