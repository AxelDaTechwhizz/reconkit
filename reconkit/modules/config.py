import os
import json
from typing import Optional


"""
Persisting cli config
"""

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.reconkit/config.json")


DEFAULTS = {
    "timeout": 20,
    "workers": 2,
    "file_format": "txt",
    "source_delay": 3.0,
    "min_delay": 1.0,
    "max_delay": 6.0,
    "verify_ssl": True,
    "save_file": False,
    "debug": False,
    "log": False,
    "profile": None 
}

def load_user_config(path=DEFAULT_CONFIG_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump(DEFAULTS, f, indent=2)
        return DEFAULTS.copy()

    try:
        with open(path, "r") as f:
            user_conf = json.load(f)
        return {**DEFAULTS, **{k: v for k, v in user_conf.items() if k in DEFAULTS}}
    except Exception:
        return DEFAULTS.copy()


def save_user_config(data, path=DEFAULT_CONFIG_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump({k: v for k, v in data.items() if k in DEFAULTS}, f, indent=2)


"""
Tech signatures for tech fingerprinting
"""
import re

TECH_SIGNATURES = {
    # --- CMS ---
    "WordPress": {
        "category": "CMS",
        "headers": [re.compile(r"x-powered-by\s*:\s*wordpress", re.I)],
        "cookies": [re.compile(r"^wp\-.*", re.I)],
        "content": [
            re.compile(r"wp-content", re.I),
            re.compile(r"wp-includes", re.I),
            re.compile(r"https?://wordpress\.org", re.I),
            re.compile(r"wp-json", re.I)
        ],
        "html": [
            {"tag": "meta", "attrs": {"name": "generator", "content_re": re.compile(r"WordPress", re.I)}},
            {"selector": "link[rel='https://api.w.org/']"},
            {"selector": "script[src*='wp-content']"}
        ]
    },
    "Joomla": {
        "category": "CMS",
        "content": [
            re.compile(r"/media/system/js/", re.I),
            re.compile(r"\bjoomla\b", re.I),
            re.compile(r"/templates/[^\"'>]*joomla", re.I)
        ],
        "html": [
            {"tag": "meta", "attrs": {"name": "generator", "content_re": re.compile(r"Joomla", re.I)}},
            {"selector": "script[src*='media/system/js']"}
        ]
    },
    "Drupal": {
        "category": "CMS",
        "headers": [re.compile(r"x-generator\s*:\s*drupal", re.I)],
        "content": [
            re.compile(r"/sites/default/files/", re.I),
            re.compile(r"drupal-settings-json", re.I),
            re.compile(r"drupal\.js", re.I)
        ],
        "html": [
            {"tag": "meta", "attrs": {"name": "Generator", "content_re": re.compile(r"Drupal", re.I)}},
            {"selector": "script[src*='drupal.js']"}
        ]
    },
    "Shopify": {
        "category": "CMS",
        "headers": [re.compile(r"x-shopify-stage", re.I)],
        "content": [
            re.compile(r"cdn\.shopify\.com", re.I),
            re.compile(r"\bShopify\b", re.I),
            re.compile(r"shopify\.assets\.js", re.I)
        ],
        "html": [
            {"selector": "script[src*='cdn.shopify.com']"},
            {"selector": "meta[name='shopify-checkout-api-token']"}
        ]
    },
    "Ghost": {
        "category": "CMS",
        "headers": [re.compile(r"x-ghost-cache", re.I)],
        "content": [
            re.compile(r"content/images", re.I),
            re.compile(r"ghost\.org", re.I),
            re.compile(r"<meta name=[\"']generator[\"'] content=[\"']Ghost", re.I)
        ],
        "html": [
            {"tag": "meta", "attrs": {"name": "generator", "content_re": re.compile(r"Ghost", re.I)}},
            {"selector": "script[src*='ghost.js']"}
        ]
    },
    "Wix": {
        "category": "CMS",
        "headers": [re.compile(r"x-wix-request-id", re.I)],
        "content": [
            re.compile(r"static\.wixstatic\.com", re.I),
            re.compile(r"wix-code", re.I)
        ],
        "html": [
            {"selector": "script[src*='wixstatic.com']"},
            {"selector": "div[id^='WIX']"}
        ]
    },
    "Squarespace": {
        "category": "CMS",
        "content": [
            re.compile(r"squarespace\.com", re.I),
            re.compile(r"static\.squarespace\.com", re.I)
        ],
        "html": [
            {"selector": "script[src*='squarespace.com']"},
            {"selector": "meta[name='generator'][content*='Squarespace']"}
        ]
    },
    "Webflow": {
        "category": "CMS",
        "headers": [re.compile(r"x-wf-page-id", re.I)],
        "content": [
            re.compile(r"webflow\.js", re.I),
            re.compile(r"assets\.webflow\.com", re.I)
        ],
        "html": [
            {"selector": "script[src*='webflow.js']"},
            {"selector": "meta[name='generator'][content*='Webflow']"}
        ]
    },

    # --- Analytics & Tracking ---
    "Google Analytics": {
        "category": "Analytics",
        "content": [
            re.compile(r"www\.google-analytics\.com/analytics\.js", re.I),
            re.compile(r"gtag\(.*?[\"']UA-\d", re.I)
        ],
        "html": [
            {"selector": "script[src*='google-analytics.com/analytics.js']"},
            {"selector": "script:contains('gtag')"}
        ]
    },
    "Google Tag Manager": {
        "category": "Analytics",
        "content": [
            re.compile(r"www\.googletagmanager\.com/gtm\.js", re.I),
            re.compile(r"\bgtm-[\w]+", re.I)
        ],
        "html": [
            {"selector": "script[src*='googletagmanager.com/gtm.js']"},
            {"selector": "noscript > iframe[src*='googletagmanager.com']"}
        ]
    },
    "Hotjar": {
        "category": "Analytics",
        "content": [
            re.compile(r"static\.hotjar\.com/c/hotjar", re.I),
            re.compile(r"_hjSettings", re.I)
        ],
        "html": [
            {"selector": "script[src*='static.hotjar.com/c/hotjar']"},
            {"selector": "script:contains('_hjSettings')"}
        ]
    },
    "Matomo": {
        "category": "Analytics",
        "content": [
            re.compile(r"piwik\.js", re.I),
            re.compile(r"matomo\.js", re.I)
        ],
        "html": [
            {"selector": "script[src*='piwik.js']"},
            {"selector": "script[src*='matomo.js']"}
        ]
    },

    # --- JavaScript Libraries ---
    "React": {
        "category": "JavaScript Libraries",
        "content": [
            re.compile(r"data-reactroot", re.I),
            re.compile(r"react-dom", re.I),
            re.compile(r"__REACT_DEVTOOLS_GLOBAL_HOOK__", re.I),
            re.compile(r"react(\.min)?\.js", re.I)
        ],
        "html": [
            {"selector": "[data-reactroot]"},
            {"selector": "script[src*='react']"}
        ]
    },
    "Vue.js": {
        "category": "JavaScript Libraries",
        "content": [
            re.compile(r"vue(\.min)?\.js", re.I),
            re.compile(r"__VUE_DEVTOOLS_GLOBAL_HOOK__", re.I),
            re.compile(r"\bvuex\b", re.I),
            re.compile(r"vuetify", re.I)
        ],
        "html": [
            {"selector": "script[src*='vue']"},
            {"selector": "[data-vue-meta]"}
        ]
    },
    "jQuery": {
        "category": "JavaScript Libraries",
        "content": [
            re.compile(r"jquery(-[\d\.]+)?(\.min)?\.js", re.I),
            re.compile(r"\$\(document\)", re.I)
        ],
        "html": [
            {"selector": "script[src*='jquery']"},
            {"selector": "[onclick*='jQuery']"}
        ]
    },
    "AngularJS": {
        "category": "JavaScript Libraries",
        "content": [
            re.compile(r"angular(\.min)?\.js", re.I),
            re.compile(r"ng-(app|controller|model)", re.I)
        ],
        "html": [
            {"selector": "script[src*='angular']"},
            {"selector": "[ng-app]"},
            {"selector": "[ng-controller]"}
        ]
    },
    "Lodash": {
        "category": "JavaScript Libraries",
        "content": [re.compile(r"lodash(\.min)?\.js", re.I)],
        "html": [
            {"selector": "script[src*='lodash']"}
        ]
    },
    "Moment.js": {
        "category": "JavaScript Libraries",
        "content": [re.compile(r"moment(\.min)?\.js", re.I)],
        "html": [
            {"selector": "script[src*='moment']"}
        ]
    },

    # --- Misc ---
    "Google PageSpeed": {
        "category": "Misc",
        "headers": [re.compile(r"x-pagespeed", re.I)],
        "html": []
    },
    "New Relic": {
        "category": "Misc",
        "content": [
            re.compile(r"nr-data\.net", re.I),
            re.compile(r"newrelic", re.I)
        ],
        "html": [
            {"selector": "script[src*='newrelic']"},
            {"selector": "script:contains('newrelic')"}
        ]
    },
    "Bootstrap": {
        "category": "Misc",
        "content": [
            re.compile(r"bootstrap(\.min)?\.css", re.I),
            re.compile(r"class=[\"']btn btn-", re.I),
            re.compile(r"bootstrap\.bundle\.min\.js", re.I)
        ],
        "html": [
            {"selector": "link[href*='bootstrap.css']"},
            {"selector": "script[src*='bootstrap.bundle.min.js']"},
            {"selector": "[class*='btn btn-']"}
        ]
    },

    # --- Frameworks ---
    "Django": {
        "category": "Frameworks",
        "headers": [re.compile(r"x-powered-by.*django", re.I)],
        "cookies": [re.compile(r"^csrftoken$", re.I), re.compile(r"^sessionid$", re.I)],
        "content": [],
        "html": [
            {"tag": "meta", "attrs": {"name": "generator", "content_re": re.compile(r"Django", re.I)}},
            {"selector": "input[name='csrfmiddlewaretoken']"}
        ]
    },
    "Flask": {
        "category": "Frameworks",
        "headers": [
            re.compile(r"server.*werkzeug", re.I),
            re.compile(r"x-powered-by.*flask", re.I)
        ],
        "content": [re.compile(r"\bflask\b", re.I)],
        "html": []
    },
    "Laravel": {
        "category": "Frameworks",
        "cookies": [re.compile(r"laravel_session", re.I)],
        "content": [
            re.compile(r"laravel", re.I)
        ],
        "html": []
    }
}
