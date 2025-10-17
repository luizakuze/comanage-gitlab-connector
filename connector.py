#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, time, json, urllib.parse, sys
from typing import Dict, Any, List, Optional, Set
import requests
from collections import defaultdict

# TLS
import urllib3

def maybe_disable_insecure_warning(flag: bool):
    if not flag:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------- utils ----------------
def get_cfg_value(cfg_block: Dict[str,Any], key_value: str, key_env: str) -> str:
    """
    Dá prioridade a <key_value>; se vazio, tenta <key_env> lendo do ambiente.
    """
    v = (cfg_block.get(key_value) or "").strip()
    if v:
        return v
    env_name = (cfg_block.get(key_env) or "").strip()
    if not env_name:
        raise RuntimeError(f"Config: informe '{key_value}' ou '{key_env}'")
    v = os.getenv(env_name)
    if not v:
        raise RuntimeError(f"Missing env var: {env_name}")
    return v

def load_cfg(path="config.yaml") -> Dict[str,Any]:
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_pending(path: Optional[str]) -> Dict[str,Any]:
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return {}

def save_pending(path: Optional[str], data: Dict[str,Any]) -> None:
    if not path:
        return
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)

def log(*args):
    print(*args, flush=True)

# ---------------- COmanage (REST - Basic Auth) ----------------
class COmanageREST:
    def __init__(
        self,
        base_url: str,
        api_user: str,
        api_key: str,
        co_id: int,
        verify_ssl: bool,
        endpoints: Dict[str,str],
        groups_prefix: str,
    ):
        self.base = base_url.rstrip("/")
        self.auth = (api_user, api_key)       # Basic Auth
        self.co_id = co_id
        self.verify = verify_ssl
        self.ep = endpoints
        self.prefix = groups_prefix

    def _get(self, path: str, params: Optional[Dict[str,Any]] = None) -> Any:
        url = f"{self.base}/{path}"
        r = requests.get(url, auth=self.auth, params=params or {}, verify=self.verify, timeout=40)
        if not self.verify:
            # verify_ssl=false
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        r.raise_for_status()
        if not r.text:
            return {}
        try:
            return r.json()
        except Exception:
            snippet = (r.text or "")[:300].replace("\n"," ")
            log(f"[DEBUG] _get non-JSON {r.status_code} path={path} params={params} ctype={r.headers.get('Content-Type')} body={snippet}")
            return {}

    def list_gl_groups(self) -> List[Dict[str,Any]]:
        """
        Retorna [{id, name}] para grupos cujo Name começa com self.prefix.
        Shape esperado (seu ambiente):
          { "CoGroups": [ {"Id":..,"Name":..}, ... ] }
        """
        j = self._get(self.ep["list_groups"], params={"coid": self.co_id, "search.name": self.prefix})
        groups = []
        if isinstance(j, dict) and "CoGroups" in j:
            for it in j["CoGroups"]:
                name = it.get("Name")
                gid  = it.get("Id")
                if name and gid and str(name).startswith(self.prefix):
                    groups.append({"id": gid, "name": name})
        else:
            log("[WARN] list_gl_groups: JSON inesperado, ajuste o parser.")
        return groups

    def group_member_emails(self, group_id: int) -> List[str]:
        """
        1) Busca membros do grupo (co_group_members.json?co_group_id= / cogroupid / groupid)
        2) Para cada membro (CoPersonId), busca e-mails em email_addresses.json?copersonid=
        3) Retorna lista única (lowercase)
        """
        # Tente primeiro "cogroupid", que já funcionou no ambiente
        variants = [
            {"coid": self.co_id, "cogroupid": group_id},
            {"coid": self.co_id, "groupid": group_id},
            {"coid": self.co_id, "co_group_id": group_id},
            {"cogroupid": group_id},
            {"groupid": group_id},
            {"co_group_id": group_id},
        ]
        j = {}
        tried = []
        for params in variants:
            try:
                js = self._get(self.ep["group_members"], params=params)
            except requests.HTTPError as e:
                code = getattr(e.response, "status_code", None)
                log(f"[DEBUG] group_member_emails: params={params} -> HTTP {code}; tentando próxima variante")
                continue
            tried.append((params, len(js.get("CoGroupMembers") or js.get("co_group_members") or [])))
            if isinstance(js, dict) and (js.get("CoGroupMembers") or js.get("co_group_members")):
                j = js
                log(f"[DEBUG] group_member_emails: usando params={params} items={tried[-1][1]}")
                break
        if not j:
            log(f"[WARN] sem acesso ou sem itens ao listar membros do grupo {group_id}; variantes tentadas={tried}")
            return []

        emails: Set[str] = set()
        coperson_ids: List[int] = []

        if isinstance(j, dict):
            items = j.get("CoGroupMembers") or j.get("co_group_members") or []
            if not isinstance(items, list):
                items = []
            for it in items:
                # normaliza possível aninhamento {"CoGroupMember": {...}}
                node = it.get("CoGroupMember") if isinstance(it, dict) and "CoGroupMember" in it else it
                pid = None
                if isinstance(node, dict):
                    # 1) CoPersonId direto
                    pid = node.get("CoPersonId")
                    # 2) Person.Type == "CO" com Id
                    if not pid:
                        person = node.get("Person") or {}
                        if person.get("Type") == "CO" and person.get("Id"):
                            pid = int(person["Id"])
                    # 3) CoPerson  
                    if not pid and node.get("CoPerson") and node["CoPerson"].get("Id"):
                        pid = int(node["CoPerson"]["Id"])
                if pid:
                    coperson_ids.append(int(pid))
            if not coperson_ids:
                # mostra chaves do primeiro item
                first = items[0] if items else {}
                log(f"[DEBUG] group_member_emails: nenhum CoPersonId. keys_sample={list(first.keys()) if isinstance(first, dict) else type(first)}")
        else:
            log("[WARN] group_member_emails: JSON inesperado, ajuste o parser.")

        for pid in coperson_ids:
            for e in self._emails_by_coperson(pid):
                if e:
                    emails.add(e.lower())

        return sorted(emails)

    def _emails_by_coperson(self, coperson_id: int) -> List[str]:
        """
        Usa email_addresses.json?copersonid=<ID>.
        """
        j = self._get(self.ep["email_addresses"], params={"coid": self.co_id, "copersonid": coperson_id})
        out: List[str] = []
        if isinstance(j, dict) and "EmailAddresses" in j:
            for it in j["EmailAddresses"]:
                mail = it.get("Mail")
                if not mail:
                    continue
                # (a) coletar TODOS (política atual)
                out.append(mail)
        return out


# ---------------- GitLab ----------------
class GitLab:
    def __init__(self, base_url: str, token: str, verify_ssl: bool = True):
        self.base = base_url.rstrip("/") + "/api/v4"
        self.h = {"PRIVATE-TOKEN": token}
        self.verify = verify_ssl
        if not self.verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _get(self, url: str, params: Optional[Dict[str,Any]]=None) -> Any:
        r = requests.get(url, headers=self.h, params=params or {}, timeout=40, verify=self.verify)
        r.raise_for_status()
        return r.json() if r.text else {}

    def user_id_by_email_or_name(self, search: str) -> Optional[int]:
        r = requests.get(f"{self.base}/users", headers=self.h, params={"search": search},
                         timeout=40, verify=self.verify)
        r.raise_for_status()
        js = r.json()
        return js[0]["id"] if js else None

    def lookup_target_id_by_path(self, mode: str, path: str) -> Optional[int]:
        # mode: "project" | "group"
        enc = urllib.parse.quote(path, safe="")
        url = f"{self.base}/{ 'projects' if mode=='project' else 'groups' }/{enc}"
        r = requests.get(url, headers=self.h, timeout=40, verify=self.verify)
        if r.status_code == 200:
            return r.json()["id"]
        if r.status_code == 404:
            return None
        r.raise_for_status()

    def list_members(self, mode: str, target_id: int) -> Dict[int,int]:
        r = requests.get(f"{self.base}/{mode}s/{target_id}/members/all",
                         headers=self.h, timeout=40, verify=self.verify)
        r.raise_for_status()
        return { m["id"]: m["access_level"] for m in r.json() }

    def ensure_member(self, mode: str, target_id: int, user_id: int, level: int) -> str:
        url_base = f"{self.base}/{mode}s/{target_id}/members"
        payload = {"user_id": user_id, "access_level":level}

        create = requests.post(url_base, headers=self.h, json=payload,
                           timeout=40, verify=self.verify)

        # sucesso
        if create.status_code == 201:
            return "created"

        # já existe direto
        if create.status_code == 409:
            upd = requests.put(f"{url_base}/{user_id}", headers=self.h,
                               json={"access_level": level}, timeout=40, verify=self.verify)
            upd.raise_for_status()
            return "updated"

        # erro 
        msg = ""
        try:
            msg = create.json()
        except Exception:
            msg = (create.text or "").strip()

        if create.status_code == 400:
            m = msg
            # normaliza para string
            try:
                m = json.dumps(m) if isinstance(m, (dict, list)) else str(m)
            except Exception:
                m = str(m)

            # Qualquer variação indicando herança do grupo pai
            if ("via ancestor group" in m
                or "already a member of group" in m
                or "inherited membership from group" in m
                or "inherited membership" in m):
                return "inherited"  # nada a fazer

            # se for projeto e veio nível > 40, rebaixa pra 40 e tenta de novo
            if mode == "project" and level > 40:
                retry = requests.post(url_base, headers=self.h,
                                      json={"user_id": user_id, "access_level": 40},
                                      timeout=40, verify=self.verify)
                if retry.status_code in (201, 409):
                    return "created" if retry.status_code == 201 else "updated"
                raise requests.HTTPError(f"POST {url_base} -> {retry.status_code} {retry.text}")

            raise requests.HTTPError(f"POST {url_base} -> 400: {m}")

        # outros erros: propaga com texto
        raise requests.HTTPError(f"POST {url_base} -> {create.status_code}: {msg}")

    def remove_member(self, mode: str, target_id: int, user_id: int) -> None:
        r = requests.delete(f"{self.base}/{mode}s/{target_id}/members/{user_id}",
                            headers=self.h, timeout=40, verify=self.verify)
        if r.status_code in (204,404):
            return
        r.raise_for_status()

    # helpers de criação e lookup ---
    def _get_json_allow_404(self, url, params=None):
        r = requests.get(url, headers=self.h, params=params or {}, timeout=40, verify=self.verify)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json() if r.text else {}

    def get_group_by_full_path(self, full_path: str) -> Optional[dict]:
        enc = urllib.parse.quote(full_path, safe="")
        return self._get_json_allow_404(f"{self.base}/groups/{enc}")

    def create_group(self, name: str, path: str, parent_id: Optional[int] = None, visibility="private") -> dict:
        payload = {"name": name, "path": path, "visibility": visibility}
        if parent_id:
            payload["parent_id"] = parent_id
        r = requests.post(f"{self.base}/groups", headers=self.h, json=payload,
                          timeout=40, verify=self.verify)
        r.raise_for_status()
        return r.json()

    def ensure_group_hierarchy(self, full_path: str, visibility="private") -> dict:
        parts = [p for p in full_path.split("/") if p]
        cur_path = ""
        parent = None
        for part in parts:
            cur_path = f"{cur_path}/{part}" if cur_path else part
            g = self.get_group_by_full_path(cur_path)
            if not g:
                parent_id = parent["id"] if parent else None
                g = self.create_group(name=part, path=part, parent_id=parent_id, visibility=visibility)
            parent = g
        return parent

    def get_project_by_full_path(self, full_path: str) -> Optional[dict]:
        enc = urllib.parse.quote(full_path, safe="")
        return self._get_json_allow_404(f"{self.base}/projects/{enc}")

    def create_project(self, name: str, path: str, namespace_id: int, visibility="private") -> dict:
        payload = {"name": name, "path": path, "namespace_id": namespace_id, "visibility": visibility}
        r = requests.post(f"{self.base}/projects", headers=self.h, json=payload,
                          timeout=40, verify=self.verify)
        r.raise_for_status()
        return r.json()

# ---------------- nomes de grupos do COmanage ----------------
# Formato: gl:<projeto>:<repo>:<role>
SIMPLE_RE = re.compile(r"^gl:(?P<project>[^:]+):(?P<repo>[^:]+):(?P<role>[^:]+)$")

def parse_simple_token(token: str) -> Optional[Dict[str,str]]:
    m = SIMPLE_RE.match(token)
    if not m:
        return None
    return {
        "env": "prod",                              # fixo
        "mode": "project",                          # sempre projeto
        "path": f"{m['project']}/{m['repo']}",      # vira path GitLab
        "role": m["role"],
    }

def parse_any_token(token: str) -> Optional[Dict[str,str]]:
    parsed = parse_simple_token(token)
    if parsed:
        log(f"[PARSE] '{token}' -> SIMPLES path={parsed['path']} role={parsed['role']}")
        return parsed
    log(f"[SKIP] '{token}' não segue nenhum padrão esperado")
    return None

# ---------------- main loop ----------------
def run_once(cfg: Dict[str,Any]) -> None:
    # COmanage client
    co = COmanageREST(
        base_url      = cfg["source"]["base_url"],
        api_user      = cfg["source"]["api_user"],
        api_key       = get_cfg_value(cfg["source"], "api_key_value", "api_key_env"),
        co_id         = int(cfg["source"]["co_id"]),
        verify_ssl    = bool(cfg["source"].get("verify_ssl", True)),
        endpoints     = cfg["source"]["endpoints"],
        groups_prefix = cfg["source"]["groups_prefix"],
    )
    maybe_disable_insecure_warning(co.verify)

    # pendências
    pending_path = cfg["run"].get("pending_db")
    pending = load_pending(pending_path)

    # busca grupos
    groups = co.list_gl_groups()
    log(f"[INFO] grupos encontrados com prefixo '{cfg['source']['groups_prefix']}': {len(groups)}")

    # junta emails por token
    token_to_emails: Dict[str,Set[str]] = defaultdict(set)
    for g in groups:
        token = g["name"]
        parsed = parse_any_token(token)
        if not parsed:
            continue
        emails = co.group_member_emails(g["id"])
        log(f"[PARSE] token='{token}' -> {len(emails)} email(s) coletado(s)")
        for em in emails:
            token_to_emails[token].add(em)

    # para cada token, reconcilia no GitLab
    for token, emails in token_to_emails.items():
        parsed = parse_any_token(token)
        if not parsed:
            continue

        env_key = parsed.get("env", "prod")
        mode    = parsed.get("mode", "project")
        path    = parsed["path"]
        role    = parsed["role"]

        base = cfg["gitlab"]["env_map"].get(env_key)
        if not base:
            log(f"[WARN] env '{env_key}' sem base_url mapeada (token={token})")
            continue

        # cliente GitLab
        gl_token  = get_cfg_value(cfg["gitlab"], "token_value", "token_env")
        gl_verify = bool(cfg["gitlab"].get("verify_ssl", True))
        gl        = GitLab(base, gl_token, verify_ssl=gl_verify)

        dry = bool(cfg["run"]["dry_run"])

        # ---------------- resolver/criar alvo ----------------
        target    = None
        target_id = None

        if mode == "project":
            # tenta achar projeto
            target = gl.get_project_by_full_path(path)
            if not target:
                if cfg["gitlab"].get("auto_create_projects", False):
                    visibility = cfg["gitlab"].get("default_visibility", "private")

                    if "/" not in path:
                        log(f"[ERROR] path de projeto sem '/': {path}")
                        continue

                    group_path, project_slug = path.split("/", 1)

                    # root_group opcional
                    root_group      = (cfg["gitlab"].get("root_group") or "").strip()
                    full_group_path = f"{root_group}/{group_path}".strip("/") if root_group else group_path

                    # garantir grupo
                    if cfg["gitlab"].get("auto_create_groups", False):
                        if dry:
                            log(f"[DRY] ensure group '{full_group_path}' (create hierarchy if missing)")
                            group_id = 0   # id simulado para seguir no dry-run
                        else:
                            grp      = gl.ensure_group_hierarchy(full_group_path, visibility=visibility)
                            group_id = grp["id"]
                    else:
                        grp = gl.get_group_by_full_path(full_group_path)
                        if not grp:
                            log(f"[WARN] grupo '{full_group_path}' não existe e auto_create_groups=false")
                            continue
                        group_id = grp["id"]

                    # criar projeto (ou simular)
                    if dry:
                        log(f"[DRY] create project '{project_slug}' under group '{full_group_path}' (ns {group_id if group_id else 'dry'})")
                        target_id = -1   # marca especial de "criado" no dry-run
                    else:
                        proj   = gl.create_project(name=project_slug, path=project_slug,
                                                   namespace_id=group_id, visibility=visibility)
                        target = proj
                else:
                    log(f"[WARN] project path '{path}' não encontrado e auto_create_projects=false")
                    continue

            if target and target_id is None:
                target_id = target["id"]

        else:
            target_id = gl.lookup_target_id_by_path(mode, path)
            if not target_id:
                log(f"[WARN] {mode} path '{path}' não encontrado em {base}")
                continue
        # -------------- fim resolver/criar alvo --------------

        # mapeia role -> level
        role_map = cfg["roles"]
        if role not in role_map:
            log(f"[WARN] role '{role}' sem mapeamento (token={token})")
            continue
        level = int(role_map[role])

        # ajuste automático: Owner(50) não existe em projeto
        if mode == "project" and level > 40:
            log(f"[INFO] ajustando role {role} (level {level}) para Maintainer (40) em projeto")
            level = 40

        # --- reconciliação de membros ---
        remove_absent = True
        for pol in cfg.get("policies", []):
            if re.match(pol["match"], token):
                remove_absent = bool(pol.get("remove_absent", True))
                break

        protect = set(int(x) for x in cfg["gitlab"].get("protect_never_remove", []))

        # Se estamos em dry-run e o projeto acabou de ser "criado" só de mentirinha, não há membros pra consultar
        if dry and target_id == -1:
            log(f"[DRY] pular reconciliação de membros para {mode} {path} (id simulado)")
            continue

        truth_ids: Set[int] = set()
        for em in sorted(emails):
            uid = gl.user_id_by_email_or_name(em)
            if uid:
                truth_ids.add(uid)
                if dry:
                    log(f"[DRY] ensure {mode} {path} (id {target_id}) <- {em} (uid {uid}) role {level}")
                else:
                    res = gl.ensure_member(mode, target_id, uid, level)
                    log(f"[OK] {res} {mode} {path} (id {target_id}) <- {em} (uid {uid}) role {level}")
                    pending.get(token, {}).pop(em, None)
            else:
                entry = pending.setdefault(token, {})
                entry[em] = {"reason": "user_not_found_in_gitlab", "ts": int(time.time())}
                log(f"[PENDING] {em} ainda não existe no GitLab ({base})")

        # remoções
        try:
            current = gl.list_members(mode, target_id)
        except requests.HTTPError as e:
            log(f"[WARN] list_members falhou para {mode} {path}: {e}")
            current = {}

        for uid in list(current.keys()):
            if uid in protect:
                continue
            if uid not in truth_ids:
                if dry:
                    log(f"[DRY] REMOVE {mode} {path} (id {target_id}) -> uid {uid}")
                else:
                    if remove_absent:
                        gl.remove_member(mode, target_id, uid)
                        log(f"[OK] removed {mode} {path} uid {uid}")

    # fim do for; persistir pendências
    save_pending(pending_path, pending)

def main():
    cfg = load_cfg()
    interval = int(cfg["run"].get("interval_seconds", 300))
    once = bool(cfg["run"].get("once", False))

    try:
        if once:
            run_once(cfg)
            return

        while True:
            run_once(cfg)
            time.sleep(interval)

    except KeyboardInterrupt:
        log("\n[INFO] interrompido pelo usuário.")
        sys.exit(0)

if __name__ == "__main__":
    main()