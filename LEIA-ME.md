# Perguntez — publicação no Cloudflare Pages ou Workers

O Perguntez é uma aplicação full-stack. A interface fica em `public/`, a API
fica em `public/_worker.js` (Pages Advanced Mode) e os dados ficam no Cloudflare
D1. **Não publique somente o `index.html`**: o `_worker.js` e o binding D1 são
necessários para login, cadastro, perguntas, respostas e recursos sociais.

## Opção A — Cloudflare Pages (para quem quer usar Pages)

### 1. Publique a pasta correta

No Cloudflare Pages, use como diretório de saída/publicação a pasta **`public`**,
que contém diretamente:

- `index.html`
- `_worker.js`
- `_headers`

Se fizer upload pelo painel, extraia o ZIP e envie **o conteúdo da pasta
`perguntez/public/`** (ou selecione a pasta `public`). Não envie a pasta externa
`perguntez/` nem o ZIP inteiro com a pasta `public` aninhada.

O arquivo `_worker.js` precisa ficar na raiz do diretório publicado. Ele usa o
modo avançado do Pages e encaminha os arquivos estáticos por `env.ASSETS`.

Para publicar pelo terminal, dentro desta pasta do projeto:

```bash
npm install
npx wrangler login
npx wrangler pages project create
npm run deploy:pages
```

Se o projeto Pages `perguntezsite` já existir, não execute `pages project create`
novamente; basta executar `npm run deploy:pages`.

### 2. Crie e conecte o banco D1

No painel Cloudflare:

1. Abra **Storage & Databases → D1 SQL Database** e crie um banco chamado
   `perguntez-db` (ou escolha o banco D1 que já contém seus dados).
2. Abra **Workers & Pages → perguntezsite → Settings → Bindings**.
3. Adicione um binding do tipo **D1 database**.
4. Em **Variable name**, escreva exatamente `DB`.
5. Selecione o banco `perguntez-db`.
6. Faça isso no ambiente **Production**. Se também usar URLs de Preview,
   configure o binding no ambiente Preview.
7. Salve e faça um novo deploy depois de adicionar o binding.

O nome `DB` diferencia maiúsculas e minúsculas. Sem esse binding, a API retorna
`Banco D1 não configurado`. A configuração `wrangler.jsonc` deste pacote é para Pages; não tente usar `wrangler deploy` como Worker independente sem configurar um banco D1 com o ID real.

### 3. Defina o administrador

Os nomes de administrador configurados neste projeto são **`felipe`** e **`fefe`**. O código não
contém mais uma senha padrão embutida.

- **Banco novo:** abra o site e crie a conta com o nome de usuário `felipe` ou `fefe`, usando
  seu próprio e-mail e uma senha forte. A API atribui automaticamente o cargo
  de administrador a esse nome.
- **Banco que já possui a conta `fefe`:** a migração marca a conta existente
  como administradora sem trocar sua senha.
- Para escolher outro nome, altere `ADMIN_USERNAMES` no `wrangler.jsonc` (para
  Workers) ou configure a variável `ADMIN_USERNAMES` nas variáveis do projeto
  Pages. Use nomes separados por vírgula.

Depois de alterar uma variável ou binding no painel, faça um novo deploy.


## Como testar depois da publicação

Abra `https://SEU-DOMINIO/api/status`. O resultado esperado é um JSON semelhante a:

```json
{"ok":true,"banco":"conectado","usuarios":0}
```

- **A página HTML aparece em vez do JSON:** o `_worker.js` não foi publicado na
  raiz do diretório de saída.
- **`Banco D1 não configurado`:** falta o binding D1 chamado `DB`.
- **Erro 500/503:** confira os logs do Worker/Pages e se o banco está conectado.
- **Erro 404 em `/api/status`:** a API não está sendo executada pelo Worker.

## Recursos incluídos

- Cadastro, login, logout e sessão protegida por cookie HttpOnly.
- Publicação de perguntas e respostas.
- Curtidas e avaliações positivas/negativas.
- Comentários em respostas.
- Seguir e deixar de seguir usuários.
- Mensagens entre usuários.
- Notificações e marcação como lidas.
- Perfil e foto do usuário.
- Escolha de melhor resposta.
- Exclusão de conteúdo pelo autor ou administrador.
- Painel administrativo com resumo, usuários e ações de moderação.

Os dados ficam no D1, não no navegador de cada visitante. A interface usa
`localStorage` apenas para preferências/dados auxiliares; a autenticação e as
operações principais são validadas pela API.
