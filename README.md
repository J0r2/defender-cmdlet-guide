## Abra o PowerShell (admin) e siga as instruções abaixo:


> [!TIP]
> Você pode usar o comando ```Get-MpPreference``` para validar os valores configurados enquanto realiza seus testes e ajustes, caso eles não mudem, muito provavelmente o Tamper Protection ou Proteção Contra Violações está ativo, você precisa desativar para o Windows Defender permitir alterações via linha de comando, você pode fazer isso via interface ou utilizando o primeiro comando abaixo.


Desativa o Tamper Protection para conseguirmos configurar o Defender.
```
Set-MpPreference -DisableTamperProtection 1
```
Especifica qual ação automática de remediação aplicar para ameaças de nível severo. Colocar em quarentena
```
Set-MpPreference -SevereThreatDefaultAction 2
```
Especifica qual ação automática de remediação aplicar para ameaças de nível alto. Colocar em quarentena
```
Set-MpPreference -HighThreatDefaultAction 2
```
Especifica qual ação automática de remediação aplicar para ameaças de nível moderado. Colocar em quarentena
```
Set-MpPreference -ModerateThreatDefaultAction 2
```
Especifica qual ação automática de remediação aplicar para ameaças de nível baixo. Colocar em quarentena
```
Set-MpPreference -LowThreatDefaultAction 2
```
Especifica qual ação automática de remediação aplicar para ameaças de nível desconhecido. Colocar em quarentena
```
Set-MpPreference -UnknownThreatDefaultAction 2
```
Bloquear abuso de drivers assinados vulneráveis explorados. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions 6
```
Bloquear o Adobe Reader de criar processos filhos. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions 6
```
Bloquear todos os aplicativos do Office de criarem processos filhos. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions 6
```
Bloquear roubo de credenciais do subsistema de segurança local do Windows (lsass.exe). Auditar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions 2
```
Bloquear conteúdo executável de cliente de e-mail e webmail. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 -AttackSurfaceReductionRules_Actions 6
```
Bloquear arquivos executáveis de serem executados a menos que atendam a critérios de prevalência, idade ou lista confiável. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions 6
```
Bloquear execução de scripts potencialmente ofuscados. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids 5beb7efe-fd9a-4556-801d-275e5ffc04cc -AttackSurfaceReductionRules_Actions 6
```
Bloquear JavaScript ou VBScript de iniciar conteúdo executável baixado. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions 6
```
Bloquear aplicativos do Office de criarem conteúdo executável. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions 6
```
Bloquear aplicativos do Office de injetarem código em outros processos. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions 6
```
Bloquear aplicativo de comunicação do Office de criar processos filhos. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions 6
```
Bloquear persistência através de assinatura de evento WMI. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions 6
```
Bloquear criação de processos originados por comandos PSExec e WMI. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions 6
```
Bloquear reinicialização da máquina em Modo de Segurança. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids 33ddedf1-c6e0-47cb-833e-de6133960387 -AttackSurfaceReductionRules_Actions 6
```
Bloquear processos não confiáveis e não assinados que são executados a partir de USB. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions 6
```
Bloquear uso de ferramentas de sistema copiadas ou personificadas. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb -AttackSurfaceReductionRules_Actions 6
```
Bloquear criação de Webshells em servidores. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids a8f5898e-1dc8-49a9-9878-85004b8a61e6 -AttackSurfaceReductionRules_Actions 6
```
Bloquear chamadas da API Win32 a partir de macros do Office. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b -AttackSurfaceReductionRules_Actions 6
```
Usar proteção avançada contra ransomware. Avisar
```
Set-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions 6
```
Especifica o nível de bloqueio na nuvem que determina quão agressivamente o Microsoft Defender verifica e bloqueia arquivos suspeitos. Moderado
```
Set-MpPreference -CloudBlockLevel 1
```
Especifica a quantidade de tempo estendido em segundos para bloquear um arquivo suspeito e verificá-lo na nuvem. 50 segundos
```
Set-MpPreference -CloudExtendedTimeout 50
```
Ativar proteção na nuvem
Especifica o tipo de associação ao Microsoft Active Protection Service. Avançado
```
Set-MpPreference -MAPSReporting 2
```
Especifica como o Windows Defender verifica o consentimento do usuário para determinadas amostras. Enviar todas as amostras
```
Set-MpPreference -SubmitSamplesConsent 3
```
Especifica o nível de detecção para aplicações potencialmente indesejadas. Habilitado
```
Set-MpPreference -PUAProtection 1
```
Especifica como o serviço de proteção de rede lida com ameaças web maliciosas, incluindo phishing e malware. Habilitado
```
Set-MpPreference -EnableNetworkProtection 1
```
Especifica se deve habilitar o bloqueio de tráfego de rede pela proteção de rede em vez de exibir um aviso. Verdadeiro
```
Set-MpPreference -EnableConvertWarnToBlock 1
```
Especifica se deve habilitar o cálculo de hash de arquivos para arquivos verificados. Verdadeiro
```
Set-MpPreference -EnableFileHashComputation 1
```
Especifica se deve atualizar o Windows Defender em conexões com medição (metered). Verdadeiro
```
Set-MpPreference -MeteredConnectionUpdates 1
```
Especifica o número de dias para manter itens na pasta de Quarentena antes de serem removidos automaticamente. 14 dias
```
Set-MpPreference -QuarantinePurgeItemsAfterDelay 14
```
Ativa o Tamper Protection para manter o Defender seguro
```
Set-MpPreference -DisableTamperProtection 0
```
