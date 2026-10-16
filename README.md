# Arca — cofre de senhas local

Gerenciador de senhas inspirado na experiência do Bitwarden, executado 100% no navegador. As credenciais ficam em **um único arquivo `.txt` criptografado** escolhido por você. Não há servidor de aplicação, conta online, telemetria nem dependências externas.

- HTML5, CSS3 e JavaScript puro (sem frameworks, sem bibliotecas, sem build)
- Web Crypto API: **AES-256-GCM** + **PBKDF2-SHA-256** (600.000 iterações por padrão)
- File System Access API para gravar diretamente no arquivo (Chrome/Edge), com fallback por download/upload nos demais navegadores

## Arquivos do projeto

| Arquivo | Função |
|---|---|
| `index.html` | Estrutura das telas (acesso e aplicação) e Content-Security-Policy |
| `style.css` | Tema claro/escuro, componentes e layout responsivo |
| `app.js` | Criptografia, leitura/gravação do arquivo, estado, interface e atalhos |
| `iniciar-cofre.sh` | Inicia o servidor local em `127.0.0.1` e abre o navegador |
| `README.md` | Esta documentação |

Nenhum arquivo extra foi necessário: o servidor HTTP (com cabeçalhos de segurança) está embutido no próprio `iniciar-cofre.sh`, e os ícones são SVG inline gerados pelo `app.js` (os ícones de projeto usam os paths do [Lucide](https://lucide.dev), embutidos no próprio arquivo — nenhuma chamada de rede).

## Requisitos

- Ubuntu (ou outra distribuição Linux) com **Python 3.7+** — já vem instalado no Ubuntu (`python3 --version`)
- Navegador moderno:
  - **Recomendado:** Google Chrome, Chromium, Microsoft Edge, Brave ou Opera (gravação direta no arquivo)
  - Firefox e Safari funcionam em **modo exportação** (veja [Compatibilidade](#compatibilidade-de-navegadores))
- Não é necessário `sudo`, Node.js ou acesso à internet

## Como iniciar

```bash
cd /caminho/para/cofre-senhas
chmod +x iniciar-cofre.sh     # apenas na primeira vez
./iniciar-cofre.sh
```

O script pode ser chamado de qualquer diretório (`~/cofre-senhas/iniciar-cofre.sh`). Ele:

1. Localiza a pasta do projeto a partir do próprio caminho
2. Verifica o Python 3 e os arquivos essenciais
3. Tenta a porta **8080**; se estiver ocupada, usa a próxima livre (até 8129)
4. Escuta **somente em `127.0.0.1`** (inacessível a outros computadores da rede)
5. Abre o navegador padrão (`xdg-open`) e mostra endereço e porta
6. Se o Arca **já estiver rodando** a partir desta pasta, apenas reabre o navegador — não inicia um segundo servidor
7. Nunca encerra processos de terceiros e nunca usa `sudo`

Opções:

```bash
ARCA_PORT=9000 ./iniciar-cofre.sh   # outra porta preferida
./iniciar-cofre.sh --no-browser     # não abre o navegador automaticamente
```

O servidor só entrega `index.html`, `style.css`, `app.js` e `README.md` — arquivos de cofre `.txt` que estejam na pasta **não** são servidos — e envia cabeçalhos `Content-Security-Policy`, `X-Frame-Options`, `nosniff` e `Cache-Control: no-store`.

## Como acessar

Abra o endereço exibido no terminal, normalmente **http://127.0.0.1:8080/**.

> Use `127.0.0.1` (ou `localhost`). A Web Crypto API e a File System Access API exigem contexto seguro; abrir o `index.html` por um endereço de rede (ex.: `http://192.168.x.x`) não funciona.

## Como encerrar o servidor

Pressione **Ctrl+C** no terminal onde o script está rodando. O servidor é finalizado e o arquivo de controle da instância é removido. Antes disso, salve o cofre (o indicador no topo deve mostrar **Salvo**).

## Criar um cofre

1. Na tela inicial, clique em **Criar novo cofre**
2. Informe o nome, a **senha mestra** (mínimo 10 caracteres, com indicador de força) e a confirmação
3. Opcional: em *Opções avançadas*, ajuste as iterações do PBKDF2 (310 mil a 2 milhões)
4. Confirme que entende que **não há recuperação** da senha mestra
5. Clique em **Criar cofre e escolher arquivo** e escolha onde salvar o `.txt`
   - Se o arquivo escolhido já tiver conteúdo, o Arca pede confirmação explícita antes de substituí-lo

## Abrir um cofre existente

- **Abrir cofre existente** → selecione o `.txt` → digite a senha mestra → **Desbloquear**
- Ou arraste o arquivo para a janela
- No Chrome/Edge, o último arquivo usado aparece como **Continuar com …** (o navegador guarda apenas a referência ao arquivo — nunca o conteúdo nem a senha)

O arquivo é validado **antes** de pedir a senha (formato, versão, parâmetros e tamanhos de salt/IV). Arquivos inválidos são recusados com uma mensagem clara e nunca são modificados. Uma senha errada exibe apenas “Senha mestra incorreta ou arquivo alterado”, sem detalhes internos. Após três tentativas erradas, cada nova tentativa espera um pouco mais.

## Salvar e exportar

| Modo | Quando | Como salva |
|---|---|---|
| **Gravação direta** | Chrome, Edge e derivados do Chromium | Grava no próprio arquivo, automaticamente ~1 s após cada alteração (pode ser desligado em Configurações). **Ctrl+S** ou o indicador do topo salvam na hora. |
| **Exportação manual** | Firefox, Safari ou permissão negada | Cada salvamento (**Ctrl+S** ou o indicador **Exportar alterações**) baixa o arquivo atualizado. Substitua a cópia antiga por ele. |

Proteções:

- O indicador no topo mostra **Salvo**, **Não salvo**, **Salvando…**, **Conflito** ou **Sem permissão**
- O navegador avisa ao fechar a aba com alterações não salvas, e o botão **Bloquear** oferece *Salvar e bloquear*
- **Antes de cada gravação**, o Arca compara o arquivo em disco com a última versão que ele mesmo gravou. Se o arquivo foi alterado por fora (outra aba, restauração de backup, sincronização), o salvamento automático é pausado e você escolhe: *Cancelar*, *Salvar como novo arquivo* ou *Sobrescrever*
- A gravação usa `createWritable()`, que escreve em um arquivo temporário e só substitui o original ao final; uma falha não corrompe o arquivo existente
- **Configurações → Salvar como…** grava em outro arquivo; **Exportar backup criptografado** baixa uma cópia com data no nome

## Backup

O arquivo `.txt` **é** o seu cofre. Se ele for perdido ou corrompido, os dados se perdem. Recomendações:

- Use **Configurações → Exportar backup criptografado** regularmente (ex.: semanalmente)
- Mantenha cópias em pelo menos dois lugares (outro disco, pen drive, nuvem pessoal). O backup é criptografado, então pode ficar em locais menos confiáveis — a segurança passa a depender da força da senha mestra
- Teste de vez em quando se um backup abre com sua senha
- Guarde a senha mestra de forma segura: **não existe recuperação**

## Uso

- **Visão geral:** indicadores (credenciais, projetos, favoritos, senhas fracas ou reutilizadas), acessos recentes, favoritos e cards de projetos
- **Credenciais:** nome, sistema, URL, usuário/e-mail, senha, projeto, categoria, observações e favorito. Criar, ver, editar e excluir (com confirmação e opção *Desfazer*). Ao trocar a senha, as 5 anteriores ficam no histórico
- **Drawer lateral:** detalhes (somente leitura), cadastro e edição. Fecha com **Esc**, pelo **×** ou clicando fora — se houver alterações pendentes, pede confirmação (clique fora não descarta nada)
- **Projetos:** nome, descrição, cor, ícone e data de criação. Ao excluir um projeto com credenciais, escolha: mover para *Sem projeto*, mover para outro projeto ou excluir também as credenciais. Também é possível criar um projeto direto no formulário da credencial
- **Pesquisa global:** nome, sistema, usuário/e-mail, domínio da URL, projeto e categoria (sem distinguir acentos). Senhas e observações **não** são pesquisadas
- **Filtros e ordenação:** projeto, categoria, favoritos; nome (A–Z/Z–A) e data de atualização
- **Gerador de senhas:** 8 a 128 caracteres, maiúsculas, minúsculas, números, símbolos, opção de evitar caracteres ambíguos, indicador de força (entropia), gerar outra, copiar e usar no formulário
- **Copiar:** usuário, senha e URL, com confirmação discreta que não mostra o conteúdo. A senha copiada é removida da área de transferência após 30 s (configurável)
- **Tema** claro/escuro (ou do sistema), salvo entre sessões
- **Bloqueio** manual e automático por inatividade (5/15/30/60 min ou nunca)

Atalhos: `/` ou `Ctrl+K` pesquisar · `N` nova credencial · `Ctrl+S` salvar · `Ctrl+Enter` salvar formulário · `Esc` fechar painel/modal.

## Modelo de criptografia

```
senha mestra ──PBKDF2-SHA-256 (salt 128 bits, N iterações)──► chave AES-256 (não exportável)
dados (JSON) ──AES-256-GCM (IV 96 bits novo a cada gravação, tag 128 bits, AAD = cabeçalho)──► ciphertext
```

Conteúdo do arquivo `.txt` (envelope JSON):

```json
{
  "format": "arca-vault",
  "version": 1,
  "app": "Arca",
  "vaultId": "2b59926a-e170-4259-8fa5-4fba301d2f4f",
  "createdAt": "2026-10-15T23:16:17.199Z",
  "updatedAt": "2026-10-15T23:16:47.210Z",
  "kdf":    { "name": "PBKDF2", "hash": "SHA-256", "iterations": 600000, "salt": "<base64, 16 bytes>" },
  "cipher": { "name": "AES-GCM", "keyLength": 256, "tagLength": 128, "iv": "<base64, 12 bytes>" },
  "ciphertext": "<base64: JSON cifrado + tag GCM>"
}
```

- **Chave:** derivada com `crypto.subtle.deriveKey` (PBKDF2, SHA-256). 600.000 iterações é o valor recomendado pela OWASP (2023) para PBKDF2-HMAC-SHA256. A chave é criada como **não exportável** e fica só na memória da aba
- **Cifra:** AES-256-GCM (criptografia autenticada). Um **IV aleatório de 12 bytes** é gerado com `crypto.getRandomValues()` a cada gravação
- **Integridade dos metadados:** formato, versão, ID do cofre, parâmetros do KDF, salt e IV entram como *Additional Authenticated Data*. Alterar qualquer um deles (ex.: reduzir as iterações) faz a descriptografia falhar
- **Conteúdo cifrado:** nome do cofre, projetos e credenciais. Ficam em claro apenas os metadados acima e as datas de criação/última gravação
- **Troca de senha mestra** (Configurações): confirma a senha atual, gera **novo salt**, permite mudar as iterações e recriptografa o cofre
- **Validação:** o envelope é validado antes de descriptografar, e os dados descriptografados são saneados (tipos, tamanhos máximos, IDs, categorias e cores válidas) antes de serem exibidos
- **Gerador:** `crypto.getRandomValues()` com amostragem por rejeição (sem viés de módulo) e embaralhamento Fisher–Yates. `Math.random()` não é usado

O formato pode ser lido por qualquer implementação padrão de PBKDF2 + AES-GCM. Os testes descriptografaram um cofre gerado pelo Arca usando apenas a Web Crypto API do Node.js.

### O que nunca é armazenado

- A senha mestra (nem em texto puro, nem como hash)
- Credenciais em texto puro no arquivo, no `localStorage`, no `sessionStorage` ou no IndexedDB
- Senhas ou chaves no console: os erros registram apenas um código genérico

O `localStorage` guarda só preferências de interface (tema, ordenação, opções do gerador, tempo de bloqueio). O IndexedDB guarda só a referência ao último arquivo aberto (Chrome/Edge).

### Ao bloquear

A referência à chave é descartada, as senhas em memória são sobrescritas por strings vazias, os objetos do cofre são liberados, drawers e modais são fechados, campos de senha são limpos e a interface é esvaziada. Antes, o Arca oferece salvar as alterações pendentes.

## Compatibilidade de navegadores

| Navegador | Criptografia | Gravação direta no arquivo | Observação |
|---|---|---|---|
| Chrome / Chromium 111+ | ✅ | ✅ | Recomendado |
| Edge 111+ | ✅ | ✅ | Recomendado |
| Brave / Opera / Vivaldi | ✅ | ✅* | *Alguns desativam a File System Access API por padrão; nesse caso usa-se o modo exportação |
| Firefox 121+ | ✅ | ❌ | Modo exportação: abrir pelo seletor de arquivos, salvar por download |
| Safari 16.4+ | ✅ | ❌ | Modo exportação |

O layout usa `:has()`, `color-mix()` e `inert`, suportados nas versões acima.

## Limitações conhecidas e de segurança

Uma aplicação puramente client-side tem limites que vale conhecer:

- **O dispositivo precisa ser confiável.** Malware, extensões maliciosas do navegador ou keyloggers podem capturar a senha mestra ou ler a página desbloqueada. Nenhum app web consegue se defender disso
- **Limpeza de memória é parcial.** JavaScript não permite apagar strings da memória: as referências são descartadas, mas cópias podem permanecer até a coleta de lixo (e eventualmente em swap). Feche a aba após o uso em computadores compartilhados
- **A área de transferência é compartilhada** com outros programas. A limpeza após 30 s só funciona se a aba estiver em foco; gerenciadores de histórico de área de transferência podem guardar cópias
- **Não há proteção contra força bruta offline além do PBKDF2.** Quem obtiver o arquivo pode testar senhas sem limite; a proteção real é uma senha mestra longa e única. O atraso após tentativas erradas só vale dentro do app
- **PBKDF2 não é “memory-hard”.** Argon2id resiste melhor a GPUs, mas não existe na Web Crypto API e exigiria biblioteca externa
- **Sem recuperação:** esquecer a senha mestra significa perder os dados
- **Sem sincronização nem edição simultânea:** abrir o mesmo cofre em duas abas gera conflito (detectado antes de sobrescrever, mas não mesclado)
- **Modo exportação** (Firefox/Safari): cada salvamento cria um novo download; o navegador pode renomeá-lo (ex.: `cofre (1).txt`). Substitua a cópia antiga manualmente
- **Datas de criação e da última gravação** ficam visíveis no envelope (não são sensíveis, mas não são cifradas)
- **Histórico de senhas** fica dentro do cofre cifrado; excluir uma credencial remove também o histórico
- O indicador de força é **aproximado** (heurística de entropia com penalidade para padrões comuns), não uma garantia
- “Acessos recentes” só é gravado no arquivo no modo de gravação direta ou no próximo salvamento manual
- A URL é aberta em nova aba com `rel="noopener noreferrer"`; somente endereços `http`/`https` são aceitos

## Testes realizados

Testes automatizados de ponta a ponta no Chromium 141 (Playwright), com os seletores de arquivo simulados pelo sistema de arquivos privado do navegador (OPFS) — o caminho real de gravação (`createWritable`) foi exercitado. **83 de 83 verificações aprovadas**, entre elas:

- Criar cofre, bloquear, desbloquear; senha errada recusada
- Arquivo sem nenhum dado em texto puro; descriptografia independente via Node.js
- CRUD de credenciais e projetos, edição preservando dados, desfazer exclusão, exclusão de projeto movendo credenciais
- Pesquisa por nome, sistema, e-mail, projeto e categoria; senhas fora da pesquisa
- Filtros, favoritos e ordenação
- Gerador: 8–128 caracteres, conjuntos, ambíguos e 30 senhas distintas com `Math.random` substituído por uma função que lança erro
- Cópia de usuário, senha e URL lida de volta da área de transferência
- Autosave, conflito com arquivo alterado externamente, arquivo inválido e metadados adulterados (sem alterar o original)
- Reabrir o arquivo em nova página, troca de senha mestra com novo salt
- Tema claro/escuro persistente, drawer e menu em tela de 390 px, ausência de rolagem horizontal
- Modo exportação (sem File System Access API): criar, baixar, reimportar
- Nenhum erro no console e nenhuma senha registrada

O script foi testado em pseudo-terminal: porta 8080 ocupada → 8081, detecção de instância já em execução, Ctrl+C encerrando o servidor e removendo o arquivo de controle.

**Não testado automaticamente:** os diálogos nativos de arquivo do sistema operacional, Firefox/Safari reais (o modo exportação foi testado no Chromium com a API desativada) e a abertura do navegador por `xdg-open` (o ambiente de testes não tinha interface gráfica).
# arca
