import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import sys
import ctypes
import json
import re

# =============================================================================
# VERIFICAÇÃO DE ADMINISTRADOR
# =============================================================================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit()

# Melhora renderização de texto (DPI Aware)
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

# =============================================================================
# DADOS E CONFIGURAÇÕES
# =============================================================================
ALL_SETTINGS = [
    # --- Ameaças por Severidade ---
    {
        "label": "Ação para ameaças de severidade máxima",
        "ps_param": "SevereThreatDefaultAction",
        "options": {"Limpar": 1, "Quarentena": 2, "Remover": 3, "Permitir": 6, "Definido pelo usuário": 8, "Sem Ação": 9, "Bloquear": 10},
        "default": "Quarentena"
    },
    {
        "label": "Ação para ameaças de alta severidade",
        "ps_param": "HighThreatDefaultAction",
        "options": {"Limpar": 1, "Quarentena": 2, "Remover": 3, "Permitir": 6, "Definido pelo usuário": 8, "Sem Ação": 9, "Bloquear": 10},
        "default": "Quarentena"
    },
    {
        "label": "Ação para ameaças de média severidade",
        "ps_param": "ModerateThreatDefaultAction",
        "options": {"Limpar": 1, "Quarentena": 2, "Remover": 3, "Permitir": 6, "Definido pelo usuário": 8, "Sem Ação": 9, "Bloquear": 10},
        "default": "Quarentena"
    },
    {
        "label": "Ação para ameaças de baixa severidade",
        "ps_param": "LowThreatDefaultAction",
        "options": {"Limpar": 1, "Quarentena": 2, "Remover": 3, "Permitir": 6, "Definido pelo usuário": 8, "Sem Ação": 9, "Bloquear": 10},
        "default": "Quarentena"
    },
    {
        "label": "Ação para ameaças desconhecidas",
        "ps_param": "UnknownThreatDefaultAction",
        "options": {"Limpar": 1, "Quarentena": 2, "Remover": 3, "Permitir": 6, "Definido pelo usuário": 8, "Sem Ação": 9, "Bloquear": 10},
        "default": "Quarentena"
    },
    
    # --- Regras ASR (Attack Surface Reduction) ---
    # NOTA: O ID (GUID) é o segundo elemento da string ps_param. O script usa regex para extraí-lo.
    {
        "label": "Bloquear abuso de drivers assinados vulneráveis explorados.",
        "ps_param": "AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },
    {
        "label": "Bloquear o Adobe Reader de criar processos filhos.",
        "ps_param": "AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },
    {
        "label": "Bloquear todos os aplicativos do Office de criarem processos filhos.",
        "ps_param": "AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },
    {
        "label": "Bloquear roubo de credenciais do LSASS.",
        "ps_param": "AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Auditar"
    },
    {
        "label": "Bloquear conteúdo executável de cliente de e-mail e webmail.",
        "ps_param": "AttackSurfaceReductionRules_Ids be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },
    {
        "label": "Bloquear execução de arquivos executáveis não confiáveis.",
        "ps_param": "AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },
    {
        "label": "Bloquear execução de scripts potencialmente ofuscados.",
        "ps_param": "AttackSurfaceReductionRules_Ids 5beb7efe-fd9a-4556-801d-275e5ffc04cc -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },
    {
        "label": "Bloquear JS/VBScript de iniciar conteúdo baixado.",
        "ps_param": "AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },
    {
        "label": "Bloquear aplicativos do Office de criarem conteúdo executável.",
        "ps_param": "AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },
    {
        "label": "Bloquear injeção de código por aplicativos do Office.",
        "ps_param": "AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },
    {
        "label": "Bloquear app de comunicação do Office de criar processos filhos.",
        "ps_param": "AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },
    {
        "label": "Bloquear persistência via WMI.",
        "ps_param": "AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },
    {
        "label": "Bloquear criação de processos via PSExec e WMI.",
        "ps_param": "AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },
    {
        "label": "Bloquear reinicialização em Modo de Segurança (Ameaça).",
        "ps_param": "AttackSurfaceReductionRules_Ids 33ddedf1-c6e0-47cb-833e-de6133960387 -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },
    {
        "label": "Bloquear processos não confiáveis a partir de USB.",
        "ps_param": "AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },
    {
        "label": "Bloquear uso de ferramentas de sistema copiadas.",
        "ps_param": "AttackSurfaceReductionRules_Ids c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },
    {
        "label": "Bloquear criação de Webshells em servidores.",
        "ps_param": "AttackSurfaceReductionRules_Ids a8f5898e-1dc8-49a9-9878-85004b8a61e6 -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },
    {
        "label": "Bloquear chamadas Win32 via macros do Office.",
        "ps_param": "AttackSurfaceReductionRules_Ids 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },
    {
        "label": "Usar proteção avançada contra ransomware.",
        "ps_param": "AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions",
        "options": {"Desativar": 0, "Ativar": 1, "Auditar": 2, "Avisar": 6},
        "default": "Avisar"
    },

    # --- Configurações Gerais ---
    {
        "label": "Nível de bloqueio na nuvem",
        "ps_param": "CloudBlockLevel",
        "options": {"Padrão": 0, "Moderado": 1, "Alto": 2, "Muito alto": 4, "Tolerância Zero": 6},
        "default": "Moderado"
    },
    {
        "label": "Tempo estendido (segundos) verificação nuvem",
        "ps_param": "CloudExtendedTimeout",
        "options": {"10s": 10, "20s": 20, "30s": 30, "40s": 40, "50s (Máx)": 50},
        "default": "50s (Máx)"
    },
    {
        "label": "Associação ao MAPS (Microsoft Active Protection Service)",
        "ps_param": "MAPSReporting",
        "options": {"Desabilitado": 0, "Básico": 1, "Avançado": 2},
        "default": "Avançado"
    },
    {
        "label": "Consentimento de envio de amostras",
        "ps_param": "SubmitSamplesConsent",
        "options": {"Sempre perguntar": 0, "Enviar amostras seguras": 1, "Nunca enviar": 2, "Enviar todas": 3},
        "default": "Enviar todas"
    },
    {
        "label": "Proteção para aplicações potencialmente indesejadas (PUA)",
        "ps_param": "PUAProtection",
        "options": {"Desativado": 0, "Ativado": 1, "Auditar": 2},
        "default": "Ativado"
    },
    {
        "label": "Proteção de Rede (SmartScreen)",
        "ps_param": "EnableNetworkProtection",
        "options": {"Desativado": 0, "Ativado": 1, "Auditoria": 2},
        "default": "Ativado"
    },
    {
        "label": "Converter avisos de rede em bloqueio",
        "ps_param": "EnableConvertWarnToBlock",
        "options": {"Ativado": '$true', "Desativado": '$false'},
        "default": "Ativado"
    },
    {
        "label": "Cálculo de hash de arquivos",
        "ps_param": "EnableFileHashComputation",
        "options": {"Ativado": '$true', "Desativado": '$false'},
        "default": "Ativado"
    },
    {
        "label": "Atualizar em conexões medidas (4G/5G)",
        "ps_param": "MeteredConnectionUpdates",
        "options": {"Ativado": '$true', "Desativado": '$false'},
        "default": "Ativado"
    },
    {
        "label": "Dias para purgar Quarentena",
        "ps_param": "QuarantinePurgeItemsAfterDelay",
        "options": {"1 dia": 1, "7 dias": 7, "14 dias": 14, "30 dias": 30, "90 dias": 90, "365 dias": 365},
        "default": "30 dias"
    }
]

# =============================================================================
# FUNÇÕES DE BACKEND (POWERSHELL)
# =============================================================================
def run_powershell(commands):
    """Executa comandos PowerShell e retorna objeto CompletedProcess."""
    ps_commands = [f"{cmd}" for cmd in commands]
    ps_script = ";\n".join(ps_commands)
    
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    
    return subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
        capture_output=True,
        text=True,
        startupinfo=startupinfo,
        encoding='cp850'
    )

def get_defender_preferences():
    """Obtém as preferências atuais via JSON."""
    cmd = "Get-MpPreference | Select-Object * | ConvertTo-Json -Compress"
    result = run_powershell([cmd])
    
    if result.returncode != 0:
        return {}
    
    try:
        data = json.loads(result.stdout)
        return data
    except json.JSONDecodeError:
        return {}

# =============================================================================
# INTERFACE GRÁFICA (GUI)
# =============================================================================
class DefenderConfigApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Configuração Avançada do Microsoft Defender")
        self.root.geometry("750x850")
        self.root.minsize(600, 500)
        
        self.combos = {}
        self.current_prefs = {}

        # Carregamento inicial (mostra loading visual)
        self.root.config(cursor="wait")
        self.root.update()
        self.current_prefs = get_defender_preferences()
        self.root.config(cursor="")

        self._setup_ui()
        self._populate_settings()

    def _setup_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(main_frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.canvas.yview)

        self.scrollable_frame = ttk.Frame(self.canvas, padding=20)
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.bind(
            "<Configure>",
            lambda e: self.canvas.itemconfig(self.canvas_window, width=e.width)
        )

        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        footer = ttk.Frame(self.root, padding=15)
        footer.pack(side="bottom", fill="x")
        
        apply_btn = ttk.Button(footer, text="APLICAR CONFIGURAÇÕES", command=self.aplicar_configuracoes)
        apply_btn.pack(fill="x", ipady=5)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _find_option_key(self, options_dict, value_to_find):
        """Encontra a chave (Label) do combobox baseado no valor do PowerShell."""
        for label, val in options_dict.items():
            # Comparação flexível (string vs int vs bool)
            if str(val).lower() == str(value_to_find).lower():
                return label
            
            # Tratamento especial para booleans do Python/JSON vs PowerShell
            if isinstance(value_to_find, bool):
                # Se veio True do JSON, queremos '$true' ou 1
                if value_to_find and str(val) in ['$true', '1']:
                    return label
                if not value_to_find and str(val) in ['$false', '0']:
                    return label
                    
        return None

    def _get_current_asr_value(self, guid_str):
        """Extrai o valor atual de uma regra ASR específica baseado nos vetores de IDs e Actions."""
        ids = self.current_prefs.get("AttackSurfaceReductionRules_Ids", [])
        actions = self.current_prefs.get("AttackSurfaceReductionRules_Actions", [])

        # Se não for lista (ex: apenas 1 regra ativa), o JSON retorna string/int direto
        if not isinstance(ids, list): ids = [ids]
        if not isinstance(actions, list): actions = [actions]

        # Normaliza GUID para minúsculo para busca
        guid_str = guid_str.lower()
        
        try:
            # Procura o índice do GUID na lista de IDs retornada pelo Windows
            # Nota: PowerShell retorna GUIDs às vezes em maiúsculo, às vezes minúsculo
            clean_ids = [str(x).lower() for x in ids]
            
            if guid_str in clean_ids:
                index = clean_ids.index(guid_str)
                if index < len(actions):
                    return actions[index]
        except ValueError:
            pass
            
        return 0 # Default para Desativado se não encontrado

    def _populate_settings(self):
        style = ttk.Style()
        style.configure("Bold.TLabel", font=("Segoe UI", 9, "bold"))

        for setting in ALL_SETTINGS:
            item_frame = ttk.Frame(self.scrollable_frame)
            item_frame.pack(fill="x", pady=5)

            lbl = ttk.Label(item_frame, text=setting["label"], wraplength=680, style="Bold.TLabel")
            lbl.pack(anchor="w")

            combo = ttk.Combobox(item_frame, values=list(setting["options"].keys()), state="readonly")
            
            # --- Lógica de Detecção do Valor Atual ---
            current_val = None
            ps_param = setting["ps_param"]

            # Caso 1: Regras ASR (Complexo)
            if "AttackSurfaceReductionRules_Ids" in ps_param:
                # Extrai o GUID usando Regex
                match = re.search(r"Ids\s+([a-fA-F0-9\-]+)\s+", ps_param)
                if match:
                    guid = match.group(1)
                    current_val = self._get_current_asr_value(guid)
            
            # Caso 2: Configuração Padrão (Simples)
            else:
                current_val = self.current_prefs.get(ps_param)

            # Tenta encontrar o Label correspondente ao valor
            matched_label = self._find_option_key(setting["options"], current_val)

            if matched_label:
                combo.set(matched_label)
            else:
                # Se falhar ou não encontrar, usa o padrão sugerido
                if setting.get("default") in setting["options"]:
                    combo.set(setting["default"])
                else:
                    combo.current(0)

            combo.pack(fill="x", pady=(2, 0))
            self.combos[setting["ps_param"]] = (combo, setting)

    def aplicar_configuracoes(self):
        if not messagebox.askyesno("Confirmar", "Deseja aplicar estas configurações?"):
            return

        commands = []
        for param, (combo, setting) in self.combos.items():
            label = combo.get()
            valor = setting["options"][label]
            commands.append(f"Set-MpPreference -{param} {valor}")

        try:
            self.root.config(cursor="wait")
            self.root.update()
            
            result = run_powershell(commands)
            
            if result.returncode == 0:
                if result.stderr and "Error" in result.stderr:
                     messagebox.showwarning("Atenção", f"Configurações aplicadas com alertas:\n{result.stderr[:500]}...")
                else:
                    messagebox.showinfo("Sucesso", "Configurações atualizadas.")
                    # Recarrega configurações para garantir sincronia visual
                    self.current_prefs = get_defender_preferences() 
            else:
                messagebox.showerror("Erro PowerShell", f"Falha ao aplicar:\n{result.stderr}")
                
        except Exception as e:
            messagebox.showerror("Erro Crítico", str(e))
        finally:
            self.root.config(cursor="")

if __name__ == "__main__":
    root = tk.Tk()
    app = DefenderConfigApp(root)
    root.mainloop()