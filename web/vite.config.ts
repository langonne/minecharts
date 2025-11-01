import UnoCSS from '@unocss/vite'
import basicSsl from '@vitejs/plugin-basic-ssl';
import { defineConfig } from 'vite'
import path from 'path'
import fs from 'fs'

function getHtmlEntryFiles(srcDir) {
    const entry = {};

    function traverseDir(currentDir) {
        const files = fs.readdirSync(currentDir);

        files.forEach((file) => {
            const filePath = path.join(currentDir, file);
            const isDirectory = fs.statSync(filePath).isDirectory();

            if (isDirectory) {
                // If it's a directory, recursively traverse it
                traverseDir(filePath);
            } else if (path.extname(file) === '.html') {
                // If it's an HTML file, add it to the entry object
                const name = path.relative(srcDir, filePath).replace(/\..*$/, '');
                entry[name] = filePath;
            }
        });
    }

    traverseDir(srcDir);

    return entry;
}

const backendTarget = process.env.MINECHARTS_API_URL || 'http://localhost:30080'

export default defineConfig({
    root: 'src',
    server: {
        https: true,
        proxy: {
            '/api': {
                target: backendTarget,
                changeOrigin: true,
                rewrite: (path) => path.replace(/^\/api/, '')
            },
            '/ws': {
                target: backendTarget,
                changeOrigin: true,
                ws: true,
                secure: false
            }
        }
    },
    build: {
        rollupOptions: {
            input: getHtmlEntryFiles('src')
        },
        outDir: '../dist',
        emptyOutDir: true
    },
    optimizeDeps: {
        entries: 'src/**/*{.html,.css,.js}'
    },
    plugins: [
        UnoCSS(),
        basicSsl(),
    ],
})
