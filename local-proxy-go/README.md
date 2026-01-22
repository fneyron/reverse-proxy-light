# Proxy local Go (Windows, sans admin)

Ce proxy MITM en Go permet de rediriger `https://api.openai.com` vers votre proxy Cloudflare Pages et d'injecter `x-proxy-token`, sans droits admin.

## Installation (sans Go installe)
1. Si `local-proxy-go.exe` est deja present, vous pouvez passer cette etape.
2. Sinon compiler le binaire avec Go portable:
   ```bat
   build.bat
   ```

## Lancer le proxy
Option simple (interactive):
```bat
run.bat
```

Option manuelle:
```bat
local-proxy-go.exe -token <votre_proxy_token> -port 8080 -config proxy-config.yaml
```

Astuce: entourez le token de guillemets s'il contient des caracteres speciaux:
```
local-proxy-go.exe -token "<votre_proxy_token>" -config proxy-config.yaml
```

## Certificat (sans admin)
Le proxy genere un certificat CA local ici: `.goproxy\ca.pem` (cle: `.goproxy\ca.key`)

1. Ouvrir `certmgr.msc`
2. **Current User** → **Trusted Root Certification Authorities** → **Certificates**
3. Importer le fichier `.goproxy\ca.pem`

Si curl n'accepte pas le certificat, utilisez:
```bat
curl --cacert .goproxy\ca.pem -x http://127.0.0.1:8080 https://api.openai.com/v1/models
```

## Configuration VSCode
- Settings → chercher `http.proxy`
- Mettre `http://127.0.0.1:8080`
- Activer `http.proxySupport` = `on`

## Utilisation
Une fois le proxy lance et VSCode configure, l'extension continue d'appeler `api.openai.com`, mais les requetes sont envoyees vers votre Pages avec `x-proxy-token`.

## Arguments
- `-token` (obligatoire): votre token proxy
- `-port` (optionnel): port local (defaut 8080)
- `-config` (optionnel): fichier YAML de regles, ex: `proxy-config.yaml`

## Configuration YAML (simple)
Un fichier YAML peut definir des regles par host, avec un proxy par defaut.

Exemple: `proxy-config.yaml`
```yaml
default_proxy: "http://proxy:8080"
rules:
  - match: "api.openai.com"
    proxy: "DIRECT"
  - match: "*.internal.local"
    proxy: "http://corp-proxy:8080"
```

Utilisation:
```bat
local-proxy-go.exe -token <votre_proxy_token> -config proxy-config.yaml
```

Si `api.openai.com` pointe vers votre Pages, vous pouvez aussi mettre le domaine Pages dans `proxy` et omettre `-target`:
```yaml
default_proxy: "http://proxy:8080"
rules:
  - match: "api.openai.com"
    proxy: "reverse-proxy-light.pages.dev"
```

## Notes
- Seules les requetes vers `api.openai.com` sont re-ecrites.
- `default_proxy` est toujours utilise; une regle avec `proxy: "DIRECT"` conserve le proxy par defaut.
- Si une regle pointe vers un autre proxy, la connexion a ce proxy passe par `default_proxy`.
- Pour forcer un proxy sur `api.openai.com`, utilisez un schema ou un port (ex: `http://proxy:8080`).
- La CA est reutilisee si `.goproxy\ca.pem` et `.goproxy\ca.key` existent.
