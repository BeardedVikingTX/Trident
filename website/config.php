<?php
/**
 * =============================================================================
 *  TRIDENT :: Site Configuration
 * =============================================================================
 *  Central meta store. Edit values here — every page reads from this file.
 * =============================================================================
 */

return [
    'meta' => [
        'name'        => 'TRIDENT',
        'tagline'     => "Three prongs. One strike. Zero false positives.",
        'version'     => '1.0.0',
        'updated'     => '2026-09-15',
        'scanners'    => 5,
        'payloads'    => 896,
        'vectors'     => 1847,
        'signatures'  => 60,
        'providers'   => 6,        // AI providers integrated
        'repo'        => 'https://github.com/BeardedVikingTX/Trident',
        'hackerone'   => 'https://hackerone.com/beardedvikingtx',
        'site'        => 'https://beardedviking.org',
        'domain'      => 'trident.beardedviking.org',
    ],

    'funding' => [
        'relocation' => ['label' => 'Relocate to Texas',       'goal' => 50000, 'raised' => 0],
        'ai_rack'    => ['label' => 'AI Workstation Rack',     'goal' => 35000, 'raised' => 0],
        'saas'       => ['label' => 'SaaS / PTaaS Rebuild',    'goal' => 0,     'raised' => 0],
    ],

    'ai_providers' => [
        ['name' => 'Google Gemini',   'icon' => 'fa-gem',            'status' => 'active'],
        ['name' => 'OpenAI ChatGPT',  'icon' => 'fa-robot',          'status' => 'active'],
        ['name' => 'DeepSeek',        'icon' => 'fa-water',          'status' => 'active'],
        ['name' => 'Anthropic Claude','icon' => 'fa-feather',        'status' => 'active'],
        ['name' => 'Groq',            'icon' => 'fa-bolt',           'status' => 'active'],
        ['name' => 'Hugging Face',    'icon' => 'fa-face-smile',     'status' => 'active'],
        ['name' => 'Ollama (local)',  'icon' => 'fa-server',         'status' => 'planned'],
    ],
];
