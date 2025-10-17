from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect
from satosa.exception import SATOSAAuthenticationError
from satosa.context import Context
import requests
import logging
from urllib.parse import urljoin
from typing import Optional, Dict, Any, List, Union, NoReturn
from dataclasses import dataclass, field
from time import sleep
from functools import lru_cache

logger = logging.getLogger(__name__)

PENDING_USER_STATUS = [
    "Pending",
    "PendingApproval",
    "PendingConfirmation",
    "PendingVetting",
]


@dataclass
class COmanageConfig:
    """
    Configuração de conexão/credenciais da API do COmanage.
    """

    api_url: str
    api_user: str
    password: str
    co_id: str
    target_backends: List[Dict]


class COmanageAccountLinkingError(Exception):
    pass


class COmanageUserNotActiveError(Exception):
    pass


class COmanageGroupsError(Exception):
    pass


class COmanageAPIError(Exception):
    """
    Erros de API normalizados.
    """

    def __init__(self, message: str, status_code: Optional[int] = None):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class COmanageAPI:
    """
    Cliente para a REST API do COmanage Registry.
    """

    session: requests.Session
    config: COmanageConfig

    def __init__(self, config: COmanageConfig):
        self.config = config
        self.session = requests.Session()
        self.session.auth = (self.config.api_user, self.config.password)
        self.session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )

    # --------------------- HTTP helpers ---------------------

    def get_request(
        self, endpoint: str, params: Dict[str, Any]
    ) -> Union[Dict[str, Any], str]:
        url = urljoin(self.config.api_url, endpoint)
        response = self.session.get(
            url, params=params, timeout=30, verify=self.session.verify
        )
        return self.__handle_response(response)

    def post_request(
        self, endpoint: str, params: Dict[str, Any]
    ) -> Union[Dict[str, Any], str]:
        url = urljoin(self.config.api_url, endpoint)
        response = self.session.post(
            url, json=params, timeout=30, verify=self.session.verify
        )
        return self.__handle_response(response)

    def delete_request(
        self, endpoint: str, params: Optional[Dict[str, Any]] = None
    ) -> Union[Dict[str, Any], str, None]:
        url = urljoin(self.config.api_url, endpoint)
        response = self.session.delete(
            url, params=params, timeout=30, verify=self.session.verify
        )
        return self.__handle_response(response)

    def __handle_response(
        self, response: requests.Response
    ) -> Union[Dict[str, Any], str, None]:
        try:
            response.raise_for_status()
            if response.status_code == 204:
                return {}  # evita None/.get
            return response.json()
        except requests.exceptions.JSONDecodeError as exc:
            raise COmanageAPIError(
                "Invalid JSON response", status_code=response.status_code
            ) from exc
        except ValueError:
            return response.text
        except requests.exceptions.HTTPError as err:
            raise COmanageAPIError(
                message=f"Request failed: {str(err)}",
                status_code=getattr(err.response, "status_code", None),
            ) from err
        except requests.exceptions.RequestException as err:
            raise COmanageAPIError(
                message=str(err), status_code=getattr(err.response, "status_code", None)
            ) from err

    # --------------------- Lookups ---------------------

    def get_org_identity_by_mail(self, mail: str) -> Optional[Dict[str, Any]]:
        """
        Workaround de bug: NÃO usar email_addresses?search.mail (gera 500).
        Em vez disso:
        1) co_people.json?coid=<CO>&search.mail=<mail>  → pega CoPerson Id
        2) co_org_identity_links.json?copersonid=<Id>   → retorna os links
        """
        if not mail:
            raise COmanageAPIError("Empty mail provided for OrgIdentity search")

        params = {"coid": self.config.co_id, "search.mail": mail}
        res = self.get_request("registry/co_people.json", params)
        co_people = (res.get("CoPeople", []) if isinstance(res, dict) else []) or []
        if not co_people:
            return None

        co_people_sorted = sorted(
            co_people, key=lambda x: 0 if x.get("Status") == "Active" else 1
        )
        for person in co_people_sorted:
            coperson_id = person.get("Id") or (person.get("CoPerson", {}) or {}).get(
                "Id"
            )
            if not coperson_id:
                continue
            links = self.get_request(
                "registry/co_org_identity_links.json",
                {"copersonid": coperson_id},
            )
            if links and (links.get("CoOrgIdentityLinks") or []):
                return links

        return None

    def get_org_identity_by_identifier(
        self, identifier: str
    ) -> Optional[Dict[str, Any]]:
        """
        Busca OrgIdentity por identifier (ex.: eduPersonUniqueId/eptid/sub/eppn), filtrando por CO.
        """
        if not identifier:
            raise COmanageAPIError("Empty identifier provided for OrgIdentity search")

        res = self.get_request(
            "registry/org_identities.json",
            {"coid": self.config.co_id, "search.identifier": identifier},
        )
        org_identities = res.get("OrgIdentities", []) or []

        if len(org_identities) == 0:
            raise COmanageAPIError(
                "get_org_identities should return one or more results but returned 0",
                status_code=404,
            )

        org_identities = self.remove_orgs_duplicates(org_identities)

        for org_identity in org_identities:
            sleep(0.05)
            org_identity_id = org_identity["Id"]
            links = self.get_request(
                "registry/co_org_identity_links.json",
                {"orgidentityid": org_identity_id},
            )
            if links:
                return links

        return None

    def get_identifiers(self, co_person_id: int) -> List[Dict[str, Any]]:
        res = self.get_request(
            "registry/identifiers.json", {"copersonid": co_person_id}
        )
        return (res.get("Identifiers", []) if isinstance(res, dict) else []) or []

    def get_names(self, co_person_id: int) -> List[Dict[str, Any]]:
        res = self.get_request("registry/names.json", {"copersonid": co_person_id})
        return res.get("Names", [])

    def get_emails(self, co_person_id: int) -> List[Dict[str, Any]]:
        res = self.get_request(
            "registry/email_addresses.json", {"copersonid": co_person_id}
        )
        return res.get("EmailAddresses", [])

    def get_groups_by_copersonid(
        self, co_person_id: int, include_internal_groups: bool = False
    ) -> List[Dict[str, Any]]:
        res = self.get_request("registry/co_groups.json", {"copersonid": co_person_id})
        if include_internal_groups:
            return res.get("CoGroups", [])
        groups = []
        for group in res.get("CoGroups", []):
            if group["Auto"] is False and group["GroupType"] == "S":
                groups.append(group)
        return groups

    def get_group_members_by_copersonid(
        self, co_person_id: int
    ) -> List[Dict[str, Any]]:
        res = self.get_request(
            "registry/co_group_members.json", {"copersonid": co_person_id}
        )
        return res.get("CoGroupMembers", [])

    def get_co_person_id(self, identifier: str) -> Optional[int]:
        """
        Resolve CoPersonId:
          - Se parecer e-mail → via email_addresses (+ links)
          - Senão → via org_identities (+ links)
        """
        if not identifier:
            raise COmanageAPIError("Empty identifier provided for CoPersonId lookup")

        def _co_person_from_links(
            link_payload: Optional[Dict[str, Any]],
        ) -> Optional[int]:
            links = (link_payload or {}).get("CoOrgIdentityLinks") or []
            if not links:
                return None
            identities = [dict(t) for t in {tuple(l.items()) for l in links}]
            for ident in identities:
                cid = ident.get("CoPersonId")
                if cid:
                    return cid
            return None

        def _looks_like_mail(value: str) -> bool:
            return "@" in value and "." in value.split("@")[-1]

        if _looks_like_mail(identifier):
            links = self.get_org_identity_by_mail(identifier)
            return _co_person_from_links(links)

        try:
            org_identity = self.get_org_identity_by_identifier(identifier) or {}
            return _co_person_from_links(org_identity)
        except COmanageAPIError:
            # Como fallback extra, se o "identifier" era de fato um e-mail mal passado
            if _looks_like_mail(identifier):
                links = self.get_org_identity_by_mail(identifier)
                return _co_person_from_links(links)
            return None

    def get_co_people(self, co_person_id: int) -> Dict[str, Any]:
        res = self.get_request(
            f"registry/co_people/{co_person_id}.json", {"coid": self.config.co_id}
        )
        co_people = res.get("CoPeople", None)
        if not co_people:
            logger.warning("COPeople not found for co_person_id: %s", co_person_id)
            return {}
        return co_people[0]

    @staticmethod
    def remove_orgs_duplicates(org_identities: list) -> List[Dict[str, Any]]:
        org_identities = [dict(t) for t in {tuple(l.items()) for l in org_identities}]
        if len(org_identities) > 1:
            logger.warning(
                "org identities: more than one org_identity found. Using the last one!"
            )
        return org_identities

    def get_groups_by_co(self) -> List[Dict[str, Any]]:
        data = self.get_request("registry/co_groups.json", {"coid": self.config.co_id})
        return data.get("CoGroups", None)

    def add_group(self, group_name) -> Dict[str, Any]:
        payload = {
            "Version": "1.0",
            "CoId": self.config.co_id,
            "Name": group_name,
            "Description": "Group added automatically",
            "Status": "Active",
        }
        response = self.post_request("registry/co_groups.json", payload)
        payload["Id"] = response["Id"]
        return payload

    def add_group_member(self, co_group_id: int, co_person_id: int) -> Dict[str, Any]:
        payload = {
            "Version": "1.0",
            "CoGroupId": co_group_id,
            "CoPersonId": co_person_id,
            "Member": True,
        }
        return self.post_request("registry/co_group_members.json", payload)

    def remove_group_member(self, co_group_member_id: int) -> NoReturn:
        return self.delete_request(
            f"registry/co_group_members/{co_group_member_id}.json"
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


class COmanageGroups:
    """
    Operações de grupos no COmanage.
    """

    def __init__(self, api: COmanageAPI, prefix: str) -> NoReturn:
        self.__api = api
        self.__idp_groups = self.__get_idp_groups(prefix)

    @property
    def idp_groups(self) -> Dict[str, Dict[str, Any]]:
        return self.__idp_groups

    @lru_cache(maxsize=128)
    def get_idp_group(self, group_name: str) -> Optional[Dict[str, Any]]:
        return self.idp_groups.get(group_name, None)

    def get_or_create_group(self, group_name: str) -> Dict[str, Any]:
        group = self.get_idp_group(group_name)
        if group:
            group["Method"] = "GET"
        else:
            group = self.create_group(group_name)
            group["Method"] = "CREATED"
        return group

    def create_group(self, group_name: str) -> Dict[str, Any]:
        return self.__api.add_group(group_name)

    def set_member(self, co_group_id: int, co_person_id: int) -> NoReturn:
        self.__api.add_group_member(co_group_id, co_person_id)

    def remove_member(self, co_group_member_id: int) -> NoReturn:
        self.__api.remove_group_member(co_group_member_id)

    def __get_idp_groups(self, prefix: str) -> Dict[str, Dict[str, Any]]:
        groups = self.__api.get_groups_by_co()
        return filter_idp_groups(prefix, groups)

    @staticmethod
    def organize_group_members(group_members: List[Dict[str, Any]]) -> Dict[str, str]:
        mapping = {}
        for group in group_members:
            mapping[group["CoGroupId"]] = group["Id"]
        return mapping


class COmanageUser:
    """
    Representa um usuário no COmanage.
    """

    def __init__(self, identifier: str, api: COmanageAPI) -> NoReturn:
        self.__api = api
        self.__co_person_id = self.api.get_co_person_id(identifier)

        logger.debug("User %s has co_person_id %s", identifier, self.co_person_id)

        # >>> Corrigido: não usar assert; levantar erro controlado
        if not self.co_person_id:
            raise COmanageAPIError(
                f"No matching user found in COmanage (identifier: {identifier})",
                status_code=404,
            )

        co_people = self.api.get_co_people(self.co_person_id) or {}
        self.__status = co_people.get("Status", "NotFound")

        if not self.is_active:
            if self.status not in PENDING_USER_STATUS:
                raise COmanageUserNotActiveError(
                    f"COPERSON ID {self.co_person_id} is not active"
                )
            self.__ldap_uid = None
        else:
            identifier_uid = self.__get_identifier_uid()
            if not identifier_uid:
                raise COmanageAPIError(
                    f"No login identifier found for CoPerson {self.co_person_id} (expected one of: uid/eppn/reference)"
                )
            self.__ldap_uid = identifier_uid.get("Identifier")
            logger.debug("User %s is %s", self.uid, self.__status)

    @property
    def is_active(self) -> bool:
        return self.__status == "Active"

    @property
    def status(self) -> str:
        return self.__status

    @property
    def uid(self) -> str:
        return self.__ldap_uid

    @property
    def co_person_id(self) -> int:
        return self.__co_person_id

    @property
    def api(self) -> COmanageAPI:
        return self.__api

    def __get_identifier_uid(self) -> Optional[Dict[str, Any]]:
        identifiers = self.api.get_identifiers(co_person_id=self.co_person_id)
        preferred_types = {"uid", "eppn", "reference"}
        for identifier in identifiers or []:
            if identifier.get("Type") in preferred_types:
                return identifier
        logger.warning(
            "No matching identifiers found in COmanage: %s", self.co_person_id
        )
        return None

    def __get_groups(self) -> List[Dict[str, Any]]:
        return self.api.get_groups_by_copersonid(self.co_person_id)

    def get_groups(self) -> Dict[str, Dict[str, Any]]:
        return filter_groups(self.__get_groups())

    def get_idp_groups(self, prefix) -> Dict[str, Dict[str, Any]]:
        groups = self.__get_groups()
        return filter_idp_groups(prefix, groups)

    def get_group_members(self) -> List[Dict[str, Any]]:
        return self.api.get_group_members_by_copersonid(self.co_person_id)

    def __repr__(self):
        return f"<COmanageUser {self.uid}>"

    def __str__(self):
        return f"<COmanageUser {self.uid}>"


@dataclass
class UserAttributes:
    """
    Atributos do usuário extraídos do fluxo do SATOSA.
    """

    edu_person_unique_id: str
    is_member_of: list[str]
    co_manage_user: Dict[str, Any] = field(
        default_factory=lambda: {
            "COmanageUID": None,
            "COmanageUserStatus": None,
            "COmanageGroups": [],
        }
    )

    @classmethod
    def from_data(
        cls, _data: dict, prefer_attr: str = "eduPersonUniqueId"
    ) -> "UserAttributes":
        attributes = _data.attributes
        prefer_attr_norm = (prefer_attr or "eduPersonUniqueId").strip()
        edu_id = (
            attributes.get(prefer_attr_norm, [""])[0]
            or attributes.get("eduPersonUniqueId", [""])[0]
            or attributes.get("eppn", [""])[0]
            or attributes.get("eduPersonPrincipalName", [""])[0]
            or attributes.get("mail", [""])[0]
        )
        return cls(
            edu_person_unique_id=edu_id,
            is_member_of=(attributes.get("isMemberOf", [""])[0] or "").split(),
        )


class COmanageAccountLinkingMicroService(ResponseMicroService):
    """
    Microservice de enrichment + controle de acesso via COmanage.
    """

    def __init__(self, config: Dict[str, Any], *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        verify_value = config.get("verify_ssl", True)
        self.deny_on_missing: bool = config.get("deny_on_missing", True)
        self.create_if_missing: bool = config.get("create_account_if_missing", False)
        self.enrollment_flow = config.get("enrollment_flow")
        self.enrollment_url = config.get("enrollment_url")
        self.return_to = config.get("return_to")

        self.user_id_attribute: str = config.get(
            "user_id_attribute", "eduPersonUniqueId"
        )

        core_cfg = {
            k: config[k]
            for k in ("api_url", "api_user", "password", "co_id", "target_backends")
            if k in config
        }
        comanage_config = COmanageConfig(**core_cfg)

        self.api = COmanageAPI(comanage_config)
        self.api.session.verify = verify_value

        self.target_backends: List[Dict[str, Any]] = (
            comanage_config.target_backends or []
        )
        self.backend: Optional[str] = None
        self.group_prefix: str = str(config.get("group_prefix", ""))

    def process(self, context, data):
        """
        Enriquecimento + controle de acesso via COmanage.

        Regras:
          - Aplica só aos backends configurados.
          - Tenta localizar o usuário por uma LISTA de candidatos (tudo que veio do IdP):
              [user_id_attribute, eduPersonUniqueId (todos os valores), eppn,
               eduPersonPrincipalName, edupersontargetedid, sub, eptid, mail]
          - Se algum resolver CoPerson → checa status e segue.
          - Se nenhum resolver:
                • tenta por e-mail (se disponível) — erros 500/401 viram "não achou".
                • se deny_on_missing=True → bloqueia com mensagem amigável.
        """
        # 0) Apenas nos backends permitidos
        allowed = {b.get("name") for b in (self.target_backends or []) if b.get("name")}
        current_backend = getattr(context, "target_backend", None)
        if allowed and current_backend not in allowed:
            return super().process(context, data)

        # 1) Monte a lista de candidatos a identifier a partir dos atributos recebidos
        attrs = data.attributes or {}

        def _vals(key: str) -> List[str]:
            v = attrs.get(key) or []
            return [x for x in v if isinstance(x, str) and x.strip()]

        # eduPersonUniqueId pode vir com vários valores (sub, eptid, eppn, etc.) — preservar todos
        candidates_ordered: List[str] = []
        seen = set()

        for key in [
            self.user_id_attribute,  # preferido
            "eduPersonUniqueId",  # todos os valores
            "eppn",
            "eduPersonPrincipalName",
            "edupersontargetedid",  # mapeado do 'sub' em alguns fluxos SAML
            "sub",
            "eptid",
            "mail",
        ]:
            for v in _vals(key):
                if v not in seen:
                    candidates_ordered.append(v)
                    seen.add(v)

        email = _vals("mail")[0] if _vals("mail") else ""

        def _merge_uid(uid_value: str, primary_identifier: str):
            if uid_value:
                data.attributes.setdefault("COmanageUID", [uid_value])
            if primary_identifier:
                # garante que o identificador usado siga no fluxo
                data.attributes.setdefault(self.user_id_attribute, [primary_identifier])

        # 2) Tentar cada candidato até achar um CoPerson ativo com identificador de login
        last_primary_error = None
        for cand in candidates_ordered:
            try:
                com_user = COmanageUser(
                    cand, self.api
                )  # resolve CoPerson, valida status e uid
                if not com_user.is_active:
                    raise SATOSAAuthenticationError(
                        context.state,
                        f"Sua conta no COmanage não está ativa (status: {com_user.status}). "
                        "Aguarde aprovação ou contate o suporte.",
                    )
                _merge_uid(com_user.uid, cand)
                return super().process(context, data)
            except (COmanageAPIError, COmanageUserNotActiveError) as e:
                # guarda o último erro e tenta o próximo identificador
                last_primary_error = e
                continue

        # 3) Fallback por e-mail (quando autorizado/funcional)
        try:
            if not email:
                raise COmanageAPIError("Missing mail for fallback lookup")
            org_links = self.api.get_org_identity_by_mail(email) or {}
            links = org_links.get("CoOrgIdentityLinks") or []
            if not links:
                raise COmanageAPIError("COmanage user not found by mail")
            # enriquecimento mínimo: mantenha e-mail e marque UID "sintético" com o CoPersonId
            data.attributes.setdefault("mail", [email])
            _merge_uid(f"coperson:{links[0].get('CoPersonId')}", email)
            return super().process(context, data)

        except Exception as err_fallback:

            # Se tivermos URL de matrícula, redireciona para o SSA com pré-preenchimento

            if self.enrollment_url:

                from urllib.parse import urlencode

                attrs = data.attributes or {}

                qs = {
                    "return": self.return_to or "",
                    "mail": (attrs.get("mail", [""])[0] or ""),
                    "displayName": (attrs.get("displayName", [""])[0] or ""),
                    "givenName": (attrs.get("givenName", [""])[0] or ""),
                    "sn": (attrs.get("sn", [""])[0] or ""),
                }

                url = f"{self.enrollment_url}?{urlencode(qs)}"

                return Redirect(url)

            # Sem URL de matrícula configurada → comportamento antigo

            raise SATOSAAuthenticationError(
                context.state,
                "Acesso bloqueado: não encontramos um cadastro ativo no COmanage "
                "para este login via CILogon. "
                "Se você já solicitou cadastro, aguarde aprovação; "
                "caso contrário, faça o pedido de registro."
                f" (detalhe técnico: {last_primary_error} / {err_fallback})",
            )

    @staticmethod
    def get_backend_config(
        backend_name: str,
        target_backends: List[Dict[str, Any]],
        config_key: str,
        default=None,
    ) -> Any:
        for backend in target_backends:
            if backend["name"] == backend_name:
                return backend.get(config_key, default)
        return default

    def register_groups(
        self, idp_groups: List[str], comanage_user: COmanageUser
    ) -> Dict[str, Any]:
        comanage_groups = COmanageGroups(self.api, self.group_prefix)
        idp_groups_user = {}

        for group in idp_groups:
            idp_group_name = f"{self.group_prefix}_{group}"
            idp_group = comanage_groups.get_or_create_group(idp_group_name)

            logger.debug(
                "Group %s: %s - %s",
                idp_group_name,
                idp_group["Id"],
                idp_group["Method"],
            )

            idp_groups_user[idp_group_name] = {
                "Id": idp_group["Id"],
                "Method": idp_group["Method"],
            }

        logger.info("--> IDP user groups with prefix: %s", idp_groups_user)

        com_group_members_user = comanage_groups.organize_group_members(
            comanage_user.get_group_members()
        )
        logger.info("--> COMANAGER group members by user: %s", com_group_members_user)

        com_groups_user = comanage_user.get_idp_groups(self.group_prefix)
        logger.info("--> COMANAGER group by user: %s", com_groups_user)

        for idp_group, _data in com_groups_user.items():
            if idp_group not in idp_groups_user:
                logger.debug("Removing group %s from user", idp_group)
                group_member_id = com_group_members_user[_data["Id"]]
                comanage_groups.remove_member(group_member_id)

        for group_name, _data in idp_groups_user.items():
            if group_name not in com_groups_user:
                logger.debug("Adding group %s to user", group_name)
                comanage_groups.set_member(_data["Id"], comanage_user.co_person_id)

        return idp_groups_user

    def get_groups(self, comanage_user: COmanageUser) -> Dict[str, Dict[str, Any]]:
        return comanage_user.get_groups()


def filter_idp_groups(
    prefix: str, groups: List[Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    """
    Filtra grupos do tipo 'S' que começam com <prefix>_ e (por segurança)
    requer 'Open' True (ou ausente → True).
    """
    response = {}
    logger.info("---> GROUPS: %s", groups)
    logger.info("---> prefix: %s", prefix)

    for group in groups:
        if (
            group["Name"].startswith(f"{prefix}_")
            and group["GroupType"] == "S"
            and group.get("Open", True)
        ):
            response[group["Name"]] = group

    return response


def filter_groups(groups: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Filtra grupos 'S' não automáticos.
    """
    response = {}
    for group in groups:
        if group["Auto"] is False and group["GroupType"] == "S":
            response[group["Name"]] = group
    return response


if __name__ == "__main__":
    import yaml
    import argparse

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="""Teste local do COmanageAccountLinkingMicroService."""
    )
    parser.add_argument(
        "--config", type=str, required=True, help="Caminho do YAML de config"
    )
    parser.add_argument(
        "--edu-person-unique-id", type=str, required=True, help="eduPersonUniqueId"
    )
    parser.add_argument(
        "--is-member-of", type=str, required=True, help="Grupos separados por espaço"
    )
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
        config = config["config"]

    @dataclass
    class Data:
        attributes: Dict[str, List[str]]

    data = Data(
        attributes={
            "eduPersonUniqueId": [args.edu_person_unique_id],
            "isMemberOf": [args.is_member_of],
        }
    )

    context = Context()
    context.target_backend = "rubin_oidc"

    def mock_next(context, internal_data):
        return {"success": True, "data": internal_data}

    service = COmanageAccountLinkingMicroService(
        config,
        name="comanage_account_linking",
        base_url=config.get("api_url"),
    )
    service.next = mock_next
    result = service.process(context, data)
    print(f"Result: {result}")
