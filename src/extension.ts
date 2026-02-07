import * as vscode from 'vscode';
import { LoginViewProvider } from './loginViewProvider';

export function activate(context: vscode.ExtensionContext) {
    const provider = new LoginViewProvider(context.extensionUri, context);

    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(
            'windsurf-login.loginView',
            provider
        )
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('windsurf-login.showLogin', () => {
            vscode.commands.executeCommand('windsurf-login.loginView.focus');
        })
    );
}

export function deactivate() {}
