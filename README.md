# Arapuca

## Introdução

Arapuca é um Host Intrusion Prevention System (HIPS) baseado na Arquitetura Zero-Trust que trabalha mitigando a encriptação e disseminação de ransomwares em redes de IT e OT. Ou seja, deixa um computador ativamente infectado por ransomware em uma espécie de quarentena.

## Ambiente de Testes (Test Bed)

Para o test bed desta ferramenta utilizamos o QEMU, que quebra um galho fornecendo controle total de interfaces de rede vituais, melhorando o tempo de reação do Arapuca.

### Topologia Lógica

- Rede IT Corporativa (Zona A): Computadores de escritório, como RH, gestão, entre outros. Interconectada via multicast. `Addr: 230.0.0.1:1234`
- Rede OT Industrial (Zona B): Computadores de produção, como máquinas industriais, sensores, chão de fábrica. Interconectada via multicast. `Addr: 230.0.0.2:5678`
- Gateway ZTA (Router): Uma VM dedicada ou o próprio nó vítima, ainda não foi decidido.

O isolamento do sandbox e a divisão de subredes corporativas (Zona A) e industriais (Zona B) serão implementados via barramento de rede virtual nativo do QEMU, utilizando o argumento `-netdev socket`. Este modo cria uma rede multicast interna entre as VMs, isolando completamente o host e eliminando o risco de vazamento do malware.

### Criação do Test Bed

Para criar o test bed, execute o script `create_testbed.sh` certificando-se de ter a ISO de uma distro Linux numa pasta `/vms` na raiz do projeto. Para este projeto recomendamos o Alpine por ser leve e fácil de instalar.

> Você pode optar por baixar as VMs já prontas e configuradas no drive.

Os assests para o test bed, como imagem do alpine e VMs QEMU prontas estão disponíveis no [drive](https://drive.google.com/drive/folders/1VLGKYvAuvbciTpMi-WMMSg_Rqzsjn0is?usp=sharing).

### Inicialização das VMs

Para inicializar as VMs, execute o script `init_testbed.sh` com as imagens das VMs na pasta `/vms`.

O login padrão para todas as VMs é `root` com senha sendo o nome da VM (e.g. `attacker`, `victim`, `ot`).

## A ferramenta Arapuca

O Arapuca age como um daemon na VM-02 e tem como objetivo mitigar a ação do ransomware na própria VM e impedir que se espalhe para outras máquinas da rede.

O programa é escrito em Python, e é dividido nos seguintes módulos:

- File System Monitor: Utiliza a lib `inotify` para monitorar eventos de gravação em diretórios críticos. De forma simples, é um watchdog.
- Heuristic Analyzer: Implementa técnicas de análise heurística para identificar comportamentos suspeitos associados a ransomware. Mais especificamente, baseado nos eventos do watchdog calcula a Entropia de Shannon dos arquivos modificados e, se a entropia ultrapassar um limiar pré-definido (atualmente `H > 7.5`) em um volume de dados grande num curto espaço de tempo os alarmes soam.
- Network Barrier: O módulo de contenção. Ao receber um alerta, utiliza `subprocess` para invocar imediatamente regras de firewall local (`nftables` ou `iptables`), aplicando um corte Drop All e removendo as rotas para a sub-rede vítima.
- Logger: Registra as anomalias, o cálculo a entropia e outras informações relevantes num banco SQLite.

## O Ransomware de Teste

Para validar o experimento, o simulador emula três fases críticas, baseadas nas três etapas que o ransomware LockBit executa:

1. Geração de IO em grande escala: A criptografia dos arquivos. Itera rapidamente sobre arquivos plaintext, lê o conteúdo, criptografa ele utilizando AES e sobrescreve o arquivo no disco. Também altera a extensão para `.locked`.
2. Tentativa de Propagação: Também chamada de worming ou movimentação lateral. Concorrentemente à criptografia, o script abre sockets assíncronos e tenta estabelecer conexões TCP nas portas de SSH (22) e Modbus (502) da VM-03 (OT).
3. Métricas de Ataque: O mock-ransomware também grava um log local em SQLite computando quantos arquivos conseguiu criptografar e quantos pacotes enviou à rede OT antes de a conexão ser derrubada pelo Agente ZTA.

## Aplicação da Zero-Trust Architecture

Os três pilares da Arquitetura Zero-Trust que a Arapuca implementa são:

- **Assume Breach (Suposição de Violação)**: A ferramenta parte do pressuposto de que o perímetro já falhou e a máquina alvo (VM-02) está infectada e executando código malicioso.
- **Monitoramento Contínuo**: Elimina-se a ideia de *implicit trust* após a autenticação, ou seja, desconfia-se de tudo. Dessa forma, há busca contínua por anomalias que indiquem comportamento malicioso.
- **Microssegmentação**: A solução aplica um perímetro local diretamente no nível do host (VM-02). Ao detectar o ataque, a Arapuca corta a conexão com a rede OT (VM-03), garantindo **isolamento lógico**.
