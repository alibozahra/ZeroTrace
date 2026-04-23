'use strict';

// ============================================================
// AI MODEL HELPERS — Ollama API wrappers
// callOllama  → /api/generate  (zerotrace-v2, zerotrace-deepseek)
// callMistral → /api/chat      (mistral:7b-instruct-q8_0)
// ============================================================

const MODELS = {
    analysis: 'zerotrace-v2:latest',
    exploits: 'zerotrace-deepseek:latest',
    report:   'mistral:7b-instruct-q8_0'
};

async function callOllama(model, prompt, options, systemPrompt) {
    options = options || {};
    const controller = new AbortController();
    const timeoutMs  = 1800000; // 30 minutes
    const timer = setTimeout(function() { controller.abort(); }, timeoutMs);
    try {
        console.log(`  [callOllama] model=${model} prompt_len=${prompt.length}`);

        // keep_alive must be a TOP-LEVEL field — Ollama ignores it inside options
        const keepAlive = (options && options.keep_alive) ? options.keep_alive : '30m';
        const modelOptions = Object.assign({
            temperature: 0.1,
            num_ctx:     8192,
            top_p:       0.9,
            stop:        ['<|eot_id|>']
        }, options);
        delete modelOptions.keep_alive; // remove from options — belongs at top level

        const reqBody = {
            model,
            prompt,
            stream:     false,
            keep_alive: keepAlive,
            options:    modelOptions
        };
        // format must be top-level — Ollama ignores it inside options
        if (modelOptions.format) {
            reqBody.format = modelOptions.format;
            delete modelOptions.format;
        }
        if (systemPrompt) reqBody.system = systemPrompt;

        const res = await fetch('http://localhost:11434/api/generate', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            signal:  controller.signal,
            body:    JSON.stringify(reqBody)
        });
        if (!res.ok) {
            const text = await res.text();
            throw new Error(`Ollama HTTP ${res.status}: ${text.substring(0, 200)}`);
        }
        const data     = await res.json();
        const response = (data.response || '').trim();
        console.log(`  [callOllama] response_len=${response.length}`);
        if (!response) throw new Error('Ollama returned empty response — model may be unloaded or OOM');
        return response;
    } finally {
        clearTimeout(timer);
    }
}

async function callMistral(messages, options) {
    options = options || {};
    const controller = new AbortController();
    const timeoutMs  = 1800000;
    const timer = setTimeout(function() { controller.abort(); }, timeoutMs);
    try {
        console.log(`  [callMistral] messages=${messages.length} model=${MODELS.report}`);

        // keep_alive must be top-level for /api/chat too — Ollama ignores it inside options
        const keepAlive = (options && options.keep_alive) ? options.keep_alive : '30m';
        const modelOptions = Object.assign({
            temperature: 0.2,
            num_ctx:     32768,
            num_predict: 6000,
        }, options);
        delete modelOptions.keep_alive;

        const body = JSON.stringify({
            model:      MODELS.report,
            messages,
            stream:     false,
            keep_alive: keepAlive,
            options:    modelOptions
        });
        console.log(`  [callMistral] request body size: ${body.length} chars`);
        const res = await fetch('http://localhost:11434/api/chat', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            signal:  controller.signal,
            body
        });
        if (!res.ok) {
            const text = await res.text();
            throw new Error(`Mistral HTTP ${res.status}: ${text.substring(0, 200)}`);
        }
        const data    = await res.json();
        const content = ((data.message && data.message.content) || '').trim();
        console.log(`  [callMistral] response_len=${content.length}`);
        return content;
    } catch (err) {
        console.error(`  [callMistral] ERROR: ${err.message}`);
        throw err;
    } finally {
        clearTimeout(timer);
    }
}

// Chat API call — more reliable for JSON output than raw generate
async function callOllamaChat(model, systemPrompt, userMessage, options) {
    options = options || {};
    const controller = new AbortController();
    const timer = setTimeout(function() { controller.abort(); }, 1800000);
    try {
        const keepAlive2    = (options && options.keep_alive) ? options.keep_alive : '30m';
        const modelOptions2 = Object.assign({ temperature: 0.1, num_ctx: 32768, num_predict: 4000, top_p: 0.9 }, options);
        delete modelOptions2.keep_alive;
        const body = JSON.stringify({
            model,
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user',   content: userMessage  }
            ],
            stream:     false,
            keep_alive: keepAlive2,
            options:    modelOptions2
        });
        console.log(`  [callOllamaChat] model=${model} body_len=${body.length}`);
        const res = await fetch('http://localhost:11434/api/chat', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            signal:  controller.signal,
            body
        });
        if (!res.ok) {
            const text = await res.text();
            throw new Error(`Ollama chat HTTP ${res.status}: ${text.substring(0, 200)}`);
        }
        const data    = await res.json();
        const content = ((data.message && data.message.content) || '').trim();
        console.log(`  [callOllamaChat] response_len=${content.length}`);
        return content;
    } finally {
        clearTimeout(timer);
    }
}

// Unload a model from Ollama VRAM to free memory for the next model
async function unloadModel(model) {
    try {
        await fetch('http://localhost:11434/api/generate', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ model, prompt: '', keep_alive: 0, stream: false })
        });
        console.log(`[ZeroTrace] Unloaded model: ${model}`);
    } catch (err) {
        console.warn(`[ZeroTrace] Failed to unload ${model}: ${err.message}`);
    }
}

module.exports = { MODELS, callOllama, callMistral, callOllamaChat, unloadModel };
