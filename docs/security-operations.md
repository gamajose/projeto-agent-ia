# Segurança operacional

## Princípio de menor privilégio

O usuário SSH do Agent deve possuir apenas as permissões necessárias para leitura e para as unidades de monitoramento aprovadas. Não use `NOPASSWD: ALL`.

Exemplo conceitual de sudoers, a ser adaptado e validado em treinamento:

```sudoers
Cmnd_Alias AGENT_READ = /usr/bin/systemctl show *, /usr/bin/systemctl is-active *, /usr/bin/journalctl *, /usr/bin/docker ps *, /usr/bin/docker inspect *
Cmnd_Alias AGENT_MONITOR_RECOVERY = /usr/bin/systemctl start check-mk-agent.socket, /usr/bin/systemctl restart check-mk-agent.socket
agent-ia ALL=(root) NOPASSWD: AGENT_READ, AGENT_MONITOR_RECOVERY
```

O executor ainda aplica sua própria lista positiva. Sudoers não substitui a política da aplicação.

## Chaves SSH

- use `SSH_STRICT_HOST_KEY_CHECKING=true`;
- mantenha `known_hosts` separado por worker;
- valide fingerprints por canal confiável antes do primeiro acesso;
- alteração de fingerprint deve bloquear a operação;
- prefira chaves Ed25519, certificados SSH de curta duração ou Vault SSH CA;
- não armazene chave privada no repositório.

## Bastion

O Agent usa canal Paramiko `direct-tcpip`, sem `ProxyCommand` shell. O bastion deve permitir somente os destinos e portas necessários. Registre origem, usuário e destino no log do bastion.

## Vault

Configure:

```env
SECRET_BACKEND=vault
VAULT_ADDR=https://vault.exemplo:8200
VAULT_TOKEN=
VAULT_NAMESPACE=
VAULT_KV_MOUNT=secret
VAULT_SECRET_PATH=agent-ia/worker-vpn-principal
VAULT_VERIFY_TLS=true
```

Chaves suportadas no segredo KV incluem:

```text
SSH_DEFAULT_PASSWORD
SSH_PRIVATE_KEY_PASSPHRASE
SSH_BASTION_PASSWORD
SSH_BASTION_PRIVATE_KEY_PASSPHRASE
GEMINI_API_KEY
GROQ_API_KEY
OPENROUTER_API_KEY
OMNIROUTE_API_KEY
APPROVAL_SECRET
AGENT_API_TOKEN
CHECKMK_WEBHOOK_TOKEN
HELPDESK_WEBHOOK_TOKEN
```

Use políticas Vault diferentes por worker. Um worker de uma VPN não deve conseguir ler credenciais de outra zona.

## Dados enviados a modelos

Antes de chamar uma IA, o Agent remove padrões conhecidos de senha, token, chave privada, comunidade SNMP e URL de banco com senha. Mesmo assim:

- não execute ferramentas que leiam arquivos de credenciais;
- não envie dumps completos de configuração;
- limite provedores aos aprovados pela empresa;
- use Ollama/local quando o dado não puder sair do ambiente;
- revise os termos de provedores agregados pelo OmniRoute.

## Aprovação

O token de aprovação:

- é assinado por HMAC;
- expira;
- está vinculado à investigação, ao alvo e ao hash das ações;
- torna-se inválido se qualquer argumento mudar;
- não contém segredo de SSH;
- deve ser tratado como credencial temporária.

## Produção e standby

Nesses ambientes, o Agent apenas investiga e propõe. Um operador pode usar o relatório e executar manualmente conforme o processo de mudança da empresa, mas o executor automático permanece bloqueado.

## Treinamento

Treinamento permite validar ferramentas corretivas autorizadas. Reboot continua proibido pelo Agent. Caso um teste de reinicialização seja necessário, deve ocorrer fora do agente, com confirmação humana explícita e em VM descartável.

## Auditoria

Retenha:

- UUID da investigação;
- identidade do aprovador;
- digest do token, nunca o token original;
- ferramentas e argumentos;
- código de retorno;
- pós-validações;
- provedor/modelo principal e revisor;
- timestamp UTC;
- worker que executou o job.

## Rotação e resposta a incidentes

Ao suspeitar de comprometimento:

1. desabilite workers e tokens da API;
2. revogue token/política Vault;
3. rotacione chaves SSH e credenciais dos provedores;
4. preserve logs e investigações;
5. compare fingerprints do known_hosts;
6. revise aprovações e ações recentes;
7. só reative após validação em treinamento.
