# Proxy OpenAI sur Cloudflare Pages

Ce projet relaie toutes les requetes envoyees a votre URL Cloudflare Pages vers l'API OpenAI, de maniere transparente.

## Fonctionnement
- Tout chemin comme `/v1/chat/completions` est proxifie vers `https://api.openai.com/v1/chat/completions`.
- Le client n'envoie pas la cle OpenAI: le proxy l'injecte depuis une variable d'environnement.
- L'acces est protege par un token partage passe dans un header.

## Installation (Cloudflare Pages)
1. Deployer ce repo sur Cloudflare Pages (GitHub).
2. Dans **Settings → Build & deployments**:
   - Build command: laisser vide
   - Deploy command: si le champ est obligatoire, mettre `echo "skip"`
   - Output directory: `public`
3. Dans **Settings → Environment Variables**, ajouter:
   - `OPENAI_API_KEY` = votre cle OpenAI
   - `PROXY_TOKEN` = le token secret exige pour appeler le proxy

## Utilisation (API)
Appeler votre URL Pages comme `api.openai.com`:

```bash
curl https://<votre-domaine-pages>/v1/models \
  -H "x-proxy-token: <votre_proxy_token>"
```

## Utilisation (VSCode sans headers custom)
Si l'extension ne permet pas de changer l'URL ou d'ajouter des headers, utilisez le proxy local Windows (Go) qui re-route `api.openai.com` vers Cloudflare Pages et injecte `x-proxy-token`.

Voir `local-proxy-go/README.md`.
Si vous avez deja un proxy pour le reste, le proxy Go supporte un proxy amont optionnel (`-upstream`).
Vous pouvez aussi utiliser un fichier YAML de regles (`-config`).

## Notes
- Le proxy supporte le streaming (SSE).
- Les headers hop-by-hop sont retires.
- Les requetes sans `x-proxy-token` valide renvoient `401 Unauthorized`.

## Depannage
Si vous voyez `Executing user deploy command: npx wrangler deploy` dans les logs Pages, le projet est mal configure:
- Pages ne doit pas executer `wrangler deploy` pour ce repo.
- Dans Cloudflare Pages, mettez **Build command** vide, **Deploy command** vide (ou `echo "skip"` si requis), et **Output directory** = `public`.
