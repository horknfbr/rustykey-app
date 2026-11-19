// Starts the RustyKey wasm. Kept out of index.html so the CSP needs no inline script.
import init from './rustykey-ui.js';

await init({ module_or_path: './rustykey-ui_bg.wasm' });
