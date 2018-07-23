import os
import re
import peewee
from playhouse.postgres_ext import ArrayField
from datetime import datetime

from settings import SETTINGS

POSTGRES = SETTINGS.get("postgres", {})

pg_default_database = POSTGRES.get("database", "updater_db")
pg_default_user = POSTGRES.get("user", "admin")
pg_default_password = POSTGRES.get("password", "123")
pg_default_host = POSTGRES.get("host", "localhost")
pg_default_port = POSTGRES.get("port", "5432")

pg_drop_before = bool(POSTGRES.get("drop_pg_before", True))

pg_database = os.environ.get("PG_DATABASE", pg_default_database)
pg_user = os.environ.get("PG_USER", pg_default_user)
pg_password = os.environ.get("PG_PASS", pg_default_password)
pg_host = os.environ.get("PG_HOST", pg_default_host)
pg_port = os.environ.get("PG_PORT", pg_default_port)

database = peewee.PostgresqlDatabase(
    database=pg_database,
    user=pg_user,
    password=pg_password,
    host=pg_host,
    port=pg_port
)

import logging
logging.basicConfig(format='%(name)s >> [%(asctime)s] :: %(message)s', level=logging.DEBUG)
logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)

def LOGINFO_IF_ENABLED(message="\n"):
    if enable_extra_logging:
        logger.info(message)

def LOGWARN_IF_ENABLED(message="\n"):
    if enable_extra_logging:
        logger.warning(message)

def LOGERR_IF_ENABLED(message="\n"):
    if enable_exception_logging:
        logger.error(message)

def LOGVAR_IF_ENABLED(message="\n"):
    if enable_results_logging:
        logger.info(message)

enable_extra_logging = SETTINGS.get("enable_extra_logging", False)
enable_results_logging = SETTINGS.get("enable_results_logging", False)
enable_exception_logging = SETTINGS.get("enable_exception_logging", True)

drop_snyk_table_before = SETTINGS.get("drop_snyk_table_before", False)

class SNYK(peewee.Model):
    class Meta:
        database = database
        ordering = ("cve_id", )
        table_name = "vulnerabilities_snyk"
        
    id = peewee.PrimaryKeyField(null=False)
    type = peewee.TextField(default="", verbose_name="Vulnerability type")
    cve_id = peewee.TextField(default="", verbose_name="CVE ID")
    cve_url = peewee.TextField(default="", verbose_name="CVE URL")
    cwe_id = peewee.TextField(default="", verbose_name="CWE ID")
    cwe_url = peewee.TextField(default="", verbose_name="CWE URL")
    header_title = peewee.TextField(default="", verbose_name="Header Title")
    affecting_github = peewee.TextField(default="", verbose_name="Affecting Github")
    versions = peewee.TextField(default="", verbose_name="Versions")
    overview = peewee.TextField(default="", verbose_name="Overview")
    details = peewee.TextField(default="", verbose_name="Details")
    references = ArrayField(peewee.TextField, default=[], verbose_name="References", index=False)
    credit = peewee.TextField(default="", verbose_name="Cerdit")
    snyk_id = peewee.TextField(default="", verbose_name="Snyk DB ID")
    source_url = peewee.TextField(default="https://snyk.io")
    source = peewee.TextField(default="snyk", verbose_name="Vulnerability source")
    disclosed = peewee.DateTimeField(default=datetime.now, verbose_name="Disclosed time")
    published = peewee.DateTimeField(default=datetime.now, verbose_name="Published time")

    def __unicode__(self):
        return "snyk"

    def __str__(self):
        return str(self.snyk_id)

    @property
    def to_json(self):
        return dict(
            id=self.id,
            type=self.type,
            cve_id=self.cve_id,
            cve_url=self.cve_url,
            cwe_id=self.cwe_id,
            cwe_url=self.cwe_url,
            header_title=self.header_title,
            affecting_github=self.affecting_github,
            versions=self.versions,
            overview=self.overview,
            details=self.details,
            references=self.references,
            credit=self.credit,
            snyk_id=self.snyk_id,
            source=self.source,
            source_url=self.source_url,
            disclosed=self.disclosed,
            published=self.published
        )

def connect_database():
    try:
        peewee.logger.disabled = True
        if database.is_closed():
            database.connect()
        else:
            pass
        LOGVAR_IF_ENABLED("[+] Connect Postgress database")
        return True
    except peewee.OperationalError as peewee_operational_error:
        LOGERR_IF_ENABLED("[e] Connect Postgres database error: {}".format(peewee_operational_error))
    return False


def disconnect_database():
    try:
        if database.is_closed():
            pass
        else:
            database.close()
        LOGVAR_IF_ENABLED("[+] Disconnect Postgress database")
        peewee.logger.disabled = False
        return True
    except peewee.OperationalError as peewee_operational_error:
        LOGERR_IF_ENABLED("[-] Disconnect Postgres database error: {}".format(peewee_operational_error))
    peewee.logger.disabled = False
    return False

def drop_snyk_table():
    connect_database()
    if SNYK.table_exists():
        SNYK.drop_table()
    disconnect_database()

def create_snyk_table():
    connect_database()
    if not SNYK.table_exists():
        SNYK.create_table()
    disconnect_database()

def check_if_snyk_item_exists_in_postgres(snyk_id):
    connect_database()
    sid = -1
    snyks = []

    snyk_id = "%" + snyk_id

    disconnect_database()
    pass

def get_snyk_id(snyk_id_string):
    sis = re.sub(r"\D", "", snyk_id_string)
    return sis

def find_duplicates(snyk_strings):
    return list(set([x for x in snyk_strings if snyk_strings.count(x) > 1]))

def scan_database_for_snyk_ids():
    snyks_ids = []

    snyks = list(SNYK.select())
    
    if len(snyks) > 0:
        for s in snyks:
            snyk_id_string = s.to_json["snyk_id"]
            if snyk_id_string != "undefined":
                snyk_clear_id = get_snyk_id(snyk_id_string)
                snyks_ids.append(snyk_clear_id)
        print("Dublicates:")
        duplicates = find_duplicates(snyks_ids)
        print(duplicates)

    return snyks_ids

# connect_database()
# scan_database_for_snyk_ids()
# disconnect_database()