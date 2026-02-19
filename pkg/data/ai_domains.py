# Comprehensive List of GenAI and ML Service Domains
# Organized by Category — 120+ domains for Shadow AI detection

# Category map for alert enrichment
AI_DOMAIN_CATEGORIES = {
    # ═══ Major LLM Providers ═══
    "openai.com": "LLM", "api.openai.com": "LLM", "chatgpt.com": "LLM",
    "oaistatic.com": "LLM", "oaiusercontent.com": "LLM", "chat.openai.com": "LLM",
    "anthropic.com": "LLM", "claude.ai": "LLM", "api.anthropic.com": "LLM",
    "console.anthropic.com": "LLM",
    "cohere.ai": "LLM", "api.cohere.ai": "LLM", "dashboard.cohere.ai": "LLM",
    "mistral.ai": "LLM", "api.mistral.ai": "LLM", "console.mistral.ai": "LLM",
    "chat.mistral.ai": "LLM",
    "ai21.com": "LLM", "studio.ai21.com": "LLM",
    "perplexity.ai": "LLM", "pplx.ai": "LLM",
    "you.com": "LLM",
    "phind.com": "LLM",
    "poe.com": "LLM",
    "character.ai": "LLM",
    "inflection.ai": "LLM", "pi.ai": "LLM",
    "deepseeks.com": "LLM", "chat.deepseek.com": "LLM", "api.deepseek.com": "LLM",
    "x.ai": "LLM", "grok.x.ai": "LLM",

    # ═══ Google AI ═══
    "gemini.google.com": "LLM", "bard.google.com": "LLM",
    "generativelanguage.googleapis.com": "LLM",
    "ai.google.dev": "LLM", "vertexai.google.com": "LLM",
    "notebooklm.google.com": "LLM", "aistudio.google.com": "LLM",

    # ═══ Microsoft / GitHub Copilot ═══
    "githubcopilot.com": "Code AI", "copilot-proxy.githubusercontent.com": "Code AI",
    "copilot.microsoft.com": "LLM", "copilot.cloud.microsoft": "LLM",
    "bing.com/chat": "LLM", "designer.microsoft.com": "Image Gen",

    # ═══ Meta AI ═══
    "ai.meta.com": "LLM", "llama.meta.com": "LLM",

    # ═══ Image & Video Generation ═══
    "midjourney.com": "Image Gen",
    "stability.ai": "Image Gen", "stable-diffusion.com": "Image Gen",
    "clipdrop.co": "Image Gen", "dreamstudio.ai": "Image Gen",
    "runwayml.com": "Video Gen", "app.runwayml.com": "Video Gen",
    "leonardo.ai": "Image Gen", "app.leonardo.ai": "Image Gen",
    "pika.art": "Video Gen", "sora.com": "Video Gen",
    "ideogram.ai": "Image Gen",
    "playground.com": "Image Gen",
    "nightcafe.studio": "Image Gen",
    "artbreeder.com": "Image Gen",
    "hotpot.ai": "Image Gen",
    "starryai.com": "Image Gen",
    "deep-image.ai": "Image Gen",
    "deepdreamgenerator.com": "Image Gen",
    "craiyon.com": "Image Gen",
    "lexica.art": "Image Gen",
    "openart.ai": "Image Gen",
    "tensor.art": "Image Gen",
    "civitai.com": "Image Gen",
    "fal.ai": "Image Gen", "api.fal.ai": "Image Gen",
    "flux.ai": "Image Gen",
    "luma.ai": "Video Gen",
    "kaiber.ai": "Video Gen",
    "heygen.com": "Video Gen",
    "synthesia.io": "Video Gen",
    "descript.com": "Video Gen",

    # ═══ Code Assistants ═══
    "cursor.sh": "Code AI", "cursor.com": "Code AI",
    "tabnine.com": "Code AI", "api.tabnine.com": "Code AI",
    "codeium.com": "Code AI", "windsurf.com": "Code AI",
    "sourcegraph.com": "Code AI", "cody.dev": "Code AI",
    "replit.com": "Code AI", "repl.co": "Code AI",
    "gitpod.io": "Code AI",
    "codium.ai": "Code AI",
    "mutable.ai": "Code AI",
    "aider.chat": "Code AI",
    "continue.dev": "Code AI",
    "supermaven.com": "Code AI",
    "bolt.new": "Code AI",
    "v0.dev": "Code AI",

    # ═══ Audio & Speech ═══
    "elevenlabs.io": "Voice AI", "api.elevenlabs.io": "Voice AI",
    "suno.ai": "Voice AI", "app.suno.ai": "Voice AI",
    "udio.com": "Voice AI",
    "speechify.com": "Voice AI",
    "murf.ai": "Voice AI",
    "resemble.ai": "Voice AI",
    "play.ht": "Voice AI",
    "wellsaidlabs.com": "Voice AI",
    "lovo.ai": "Voice AI",
    "uberduck.ai": "Voice AI",

    # ═══ Writing & Productivity ═══
    "jasper.ai": "Writing AI", "writesonic.com": "Writing AI",
    "copy.ai": "Writing AI", "rytr.me": "Writing AI",
    "wordtune.com": "Writing AI", "grammarly.com": "Writing AI",
    "notion.so": "Writing AI",  # AI-integrated
    "mem.ai": "Writing AI",
    "otter.ai": "Writing AI",
    "fireflies.ai": "Writing AI",

    # ═══ Agent Platforms & Tools ═══
    "langchain.com": "Agent/Tool", "smith.langchain.com": "Agent/Tool",
    "crewai.com": "Agent/Tool",
    "autogen.microsoft.com": "Agent/Tool",
    "zapier.com": "Agent/Tool",
    "make.com": "Agent/Tool",
    "n8n.io": "Agent/Tool",
    "relevanceai.com": "Agent/Tool",

    # ═══ ML Infrastructure / API Providers ═══
    "huggingface.co": "ML Infra", "hf.co": "ML Infra",
    "api-inference.huggingface.co": "ML Infra",
    "replicate.com": "ML Infra", "api.replicate.com": "ML Infra",
    "modal.com": "ML Infra",
    "together.xyz": "ML Infra", "api.together.xyz": "ML Infra",
    "fireworks.ai": "ML Infra", "api.fireworks.ai": "ML Infra",
    "groq.com": "ML Infra", "api.groq.com": "ML Infra",
    "anyscale.com": "ML Infra",
    "baseten.co": "ML Infra",
    "banana.dev": "ML Infra",
    "deepinfra.com": "ML Infra",
    "cerebras.ai": "ML Infra",
    "sambanova.ai": "ML Infra",
    "octoai.cloud": "ML Infra",
    "lepton.ai": "ML Infra",
    "aws.amazon.com/bedrock": "ML Infra",

    # ═══ Research / Open Source ═══
    "arxiv.org": "Research",
    "paperswithcode.com": "Research",
    "wandb.ai": "ML Infra",
    "neptune.ai": "ML Infra",
    "mlflow.org": "ML Infra",
    "kaggle.com": "ML Infra",
}

# Set for fast lookups (backward compatible)
AI_DOMAINS = set(AI_DOMAIN_CATEGORIES.keys())

def get_ai_category(domain: str) -> str:
    """Return the AI category for a domain, or None if not an AI domain."""
    if not domain:
        return None
    domain = domain.lower().strip()

    # Exact match
    if domain in AI_DOMAIN_CATEGORIES:
        return AI_DOMAIN_CATEGORIES[domain]

    # Parent/subdomain match
    parts = domain.split('.')
    if len(parts) >= 2:
        parent = ".".join(parts[-2:])
        if parent in AI_DOMAIN_CATEGORIES:
            return AI_DOMAIN_CATEGORIES[parent]
    if len(parts) >= 3:
        grandparent = ".".join(parts[-3:])
        if grandparent in AI_DOMAIN_CATEGORIES:
            return AI_DOMAIN_CATEGORIES[grandparent]

    return None

def is_ai_domain(domain: str) -> bool:
    """
    Check if a domain or its parent is a known AI service.
    Handles exact matches and subdomains (e.g., 'cdn.openai.com' -> 'openai.com').
    """
    return get_ai_category(domain) is not None
