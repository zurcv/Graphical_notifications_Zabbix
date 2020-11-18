#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Envio de gráfico por WhatsApp, Telegram e Email através do ZABBIX (Send zabbix alerts graph WhatsApp, Telegram e Mail)
#
# Copyright (C) <2016>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Contacts:
# Eracydes Carvalho (Sansão Simonton) - Monitoring Specialist - Telegram: @sansaoipb
# Thiago Paz - NOC Analyst - thiagopaz1986@gmail.com

import os, sys, re, json, time, smtplib

if len(sys.argv) <= 2 or "--send" in sys.argv:
    dest0 = "||".join(sys.argv).split("--send")[1].replace("||", "")
    print(f"\nEste script é pra ser executado pelo ZABBIx e não manualmente.\nPara realização de teste use o script:\n\nsudo -u zabbix ./notificacoes-teste.py --send {dest0}\n")
    exit()

import requests, urllib3
from pyrogram import Client

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import email.utils
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import configparser
conf = configparser

import base64
from urllib.parse import quote

class PropertiesReaderX:
    config = None
    def __init__(self, pathToProperties):
        PropertiesReaderX.config = conf.RawConfigParser()
        PropertiesReaderX.config.read(pathToProperties)

    def getValue(self, section, key):
        # type: (object, object) -> object
        return PropertiesReaderX.config.get(section, key)

path = "{0}".format("/".join(sys.argv[0].split("/")[:-1])+"/{0}")

if sys.platform.startswith('win32') or sys.platform.startswith('cygwin') or sys.platform.startswith('darwin'):  # para debug quando estiver no WINDOWS ou no MAC
    graph_path = os.getcwd()

else:
    graph_path = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionTelegram', 'path.graph')  # Path where graph file will be save temporarily

# Zabbix settings | Dados do Zabbix ####################################################################################
zbx_server = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSection', 'url')
zbx_user = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSection', 'user')
zbx_pass = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSection', 'pass')

# Graph settings | Configuracao do Grafico #############################################################################
height = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSection', 'height')    # Graph height | Altura
width = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSection', 'width')     # Graph width  | Largura

# Ack message | Ack da Mensagem ########################################################################################
Ack = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSection', 'ack')

# Salutation | Saudação ################################################################################################
Salutation = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSection', 'salutation')
if re.search("(sim|s|yes|y)", str(Salutation).lower()):
    hora = int(time.strftime("%H"))

    if hora < 12:
        salutation = 'Bom dia'
    elif hora >= 18:
        salutation = 'Boa noite'
    else:
        salutation = 'Boa tarde'
else:
    salutation = ""

# Diretórios
# Log path | Diretório do log
projeto = sys.argv[0].split("/")[-1:][0].split(".")[0]
logName = '{0}.log'.format(projeto)
pathLogs = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSection', 'path.logs')

if "default" == pathLogs.lower():
    pathLogs = path.format("log")

arqLog = "{0}".format(os.path.join(pathLogs, logName))

if not os.path.exists(pathLogs):
    os.makedirs(pathLogs)

########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
arqJson = ".env.json"
fileX = os.path.join(pathLogs, arqJson)

import logging.config
import traceback

file = """{
    "version": 1,
    "disable_existing_loggers": false,
    "formatters": {
        "simple": {
            "format": "[%(asctime)s][%(levelname)s] - %(message)s"
        }
    },

    "handlers": {
        "file_handler": {
            "class": "logging.handlers.RotatingFileHandler",
            "maxBytes": 5242880,
            "backupCount":5,
            "level": "INFO",
            "formatter": "simple",
            "filename": "python_logging.log",
            "encoding": "utf8"
        }
    },

    "root": {
        "level": "INFO",
        "handlers": ["file_handler"]
    }
}
"""

arqConfig = "logging_configuration.json"
pathDefault = ""

class Log:
    @staticmethod
    def writelog(entry, pathfile, log_level):
        global pathDefault

        try:
            Log.log(entry, pathfile, log_level)
        except Exception:
            try:
                # if "\\" in traceback.format_exc():
                #     linha = re.search("(File)[A-Za-z0-9_\"\\\\\s:.]+", traceback.format_exc()).group()[5:].replace("\"", "")
                #     pathDefault = "{0}\\log\\".format("\\".join(linha.split("\\")[:-1]))
                # else:
                #     linha = re.search("(File)[A-Za-z0-9_\"/\s:.]+", traceback.format_exc()).group()[5:].replace("\"", "")
                #     pathDefault = "{0}/log/".format("/".join(linha.split("/")[:-1]))

                pathDefault = f"{pathLogs}/"
                arquivo = open("{0}{1}".format(pathDefault, arqConfig), "w")
                arquivo.writelines(file)
                arquivo.close()
                Log.log(entry, pathfile, log_level)
            except Exception:
                pass

    @staticmethod
    def log(entry, pathfile, log_level):
        logging.getLogger('suds.client').setLevel(logging.CRITICAL)
        logging.getLogger('suds.wsdl').setLevel(logging.CRITICAL)
        with open("{0}{1}".format(pathDefault, arqConfig), 'r+') as logging_configuration_file:
            config_dict = json.load(logging_configuration_file)
            config_dict["handlers"]["file_handler"]['filename'] = pathfile
        logging.config.dictConfig(config_dict)
        logger = logging.getLogger(__name__)
        logging.getLogger("suds").setLevel(logging.CRITICAL)

        if log_level.upper() == "INFO":
            logger.info(str(entry))
        elif log_level.upper() == "WARNING":
            logger.warning(str(entry))
        elif log_level.upper() == "CRITICAL":
            logger.critical(str(entry))
        elif log_level.upper() == "ERROR":
            logger.error(str(entry))

log = Log

nograph = "--nograph"

argvs = " || ".join(sys.argv)

if nograph not in argvs:
    try:
        itemname, eventid, itemid, color, period, body = sys.argv[3].split('#', 5)
        period = int(period)

    except ValueError as e:
        if "unpack" in str(e):
            log.writelog(
                '{0} >> at split (itemname, eventid, itemid, color, period, body) | Quantidade de argumentos insuficientes no split (itemname, eventid, itemid, color, period, body)'.format(
                    str(e)), arqLog, "ERROR")

        else:
            log.writelog('{0}'.format(str(e)), arqLog, "ERROR")
        exit()

else:
    body = "\n{0}".format(sys.argv[3])

body = re.sub(r'(\d{4})\.(\d{2})\.(\d{2})', r'\3/\2/\1', body).replace("--nograph", "").rstrip().strip()

def destinatarios(dest):
    destinatario = ["{0}".format(hostsW).strip().rstrip() for hostsW in dest.split(",")]
    return destinatario

def send_mail(dest, itemType, get_graph, key):
    # Mail settings | Configrações de e-mail ###########################################################################
    mail_from = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionEmail', 'mail.from')
    smtp_server0 = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionEmail', 'smtp.server')
    mail_user0 = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionEmail', 'mail.user')
    mail_pass0 = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionEmail', 'mail.pass')
    ####################################################################################################################

    try:
        smtp_server = decrypt(key, smtp_server0)
    except:
        smtp_server = smtp_server0

    try:
        mail_user = decrypt(key, mail_user0)
    except:
        mail_user = mail_user0

    try:
        mail_pass = decrypt(key, mail_pass0)
    except:
        mail_pass = mail_pass0


    try:
        mail_from = email.utils.formataddr(tuple(mail_from.replace(">", "").split(" <")))
    except:
        mail_from = mail_from

    dests = ', '.join(dest)
    msg = body
    msg = msg.replace("\\n", "").replace("\n", "<br>")
    try:
        subject = re.sub(r"(<(\/)?[a-z]>)", "", sys.argv[2])
    except:
        subject = sys.argv[2]

    msgRoot = MIMEMultipart('related')
    msgRoot['Subject'] = subject
    msgRoot['From'] = mail_from
    msgRoot['To'] = dests

    msgAlternative = MIMEMultipart('alternative')
    msgRoot.attach(msgAlternative)

    saudacao = salutation
    Saudacao = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionEmail', 'salutation.email')

    if re.search("(sim|s|yes|y)", str(Saudacao).lower()):
        if saudacao:
            saudacao = "<p>{0},</p>".format(salutation)
    else:
        saudacao = ""

    text = '{0}<p>{1}</p>'.format(saudacao, msg)

    if re.search("(0|3)", itemType):
        URL = "{0}/history.php?action=showgraph&itemids[]={1}"
        text += '<br><a href="{0}"><img src="cid:image1"></a>'.format(URL.format(zbx_server, itemid))
        msgImage = MIMEImage(get_graph.content)
        msgImage.add_header('Content-ID', '<image1>')
        msgRoot.attach(msgImage)

    msgText = MIMEText(text, 'html', _charset='utf-8')
    msgAlternative.attach(msgText)

    try:
        smtp = smtplib.SMTP(smtp_server)
        smtp.ehlo()

        try:
            smtp.starttls()
        except Exception:
            pass

        try:
            smtp.login(mail_user, mail_pass)
        except smtplib.SMTPAuthenticationError as msg:
            # print("Error: Unable to send email | Não foi possível enviar o e-mail - {0}".format(msg.smtp_error.decode("utf-8").split(". ")[0]))
            log.writelog('Error: Unable to send email | Não foi possível enviar o e-mail - {0}'.format(msg.smtp_error.decode("utf-8").split(". ")[0]), arqLog, "WARNING")
            smtp.quit()
            exit()
        except smtplib.SMTPException:
            pass

        try:
            smtp.sendmail(mail_from, dest, msgRoot.as_string())
        except Exception as msg:
            # print("Error: Unable to send email | Não foi possível enviar o e-mail - {0}".format(msg.smtp_error.decode("utf-8").split(". ")[0]))
            log.writelog('Error: Unable to send email | Não foi possível enviar o e-mail - {0}'.format(msg.smtp_error.decode("utf-8").split(". ")[0]), arqLog,
                         "WARNING")
            smtp.quit()
            exit()

        if re.search("(sim|s|yes|y)", str(Ack).lower()):
            if nograph not in argvs:
                ack(dests, "Email enviado com sucesso ({0})")

        # print("Email sent successfully | Email enviado com sucesso ({0})".format(dests))
        log.writelog('Email sent successfully | Email enviado com sucesso ({0})'.format(dests), arqLog, "INFO")
        smtp.quit()
    except smtplib.SMTPException as msg:
        # print("Error: Unable to send email | Não foi possível enviar o e-mail ({0})".format(msg))
        log.writelog('Error: Unable to send email | Não foi possível enviar o e-mail ({0})'.format(msg), arqLog, "WARNING")
        logout_api()
        smtp.quit()
        exit()

def send_telegram(Ldest, itemType, get_graph, key):
    # Telegram settings | Configuracao do Telegram #########################################################################
    api_id0 = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionTelegram', 'api.id')
    api_hash0 = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionTelegram', 'api.hash')

    try:
        api_id = int(decrypt(key, api_id0))
    except:
        api_id = api_id0

    try:
        api_hash = str(decrypt(key, api_hash0))
    except:
        api_hash = api_hash0

    app = Client("SendGraph", api_id=api_id, api_hash=api_hash)

    msg = body.replace("\\n", "")
    saudacao = salutation
    Saudacao = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionTelegram', 'salutation.telegram')

    if re.search("(sim|s|yes|y)", str(Saudacao).lower()):
        if saudacao:
            saudacao = salutation + " {0} \n\n"
    else:
        saudacao = ""


    with app:
        for dest in Ldest:
            dest = dest.lower()
            if re.search("user#|chat#|\'|\"", dest):
                if "#" in dest:
                    dest = dest.split("#")[1]

                elif dest.startswith("\"") or dest.startswith("\'"):
                    dest = dest.replace("\"", "").replace("\'", "")

            elif dest.startswith("@"):
                dest = dest[1:]

            flag = True
            while flag:
                try:
                    Contatos = app.get_contacts()
                    for contato in Contatos:
                        Id = f"{contato.id}"
                        nome = f"{contato.first_name}"
                        if contato.last_name:
                            nome += f" {contato.last_name}"

                        username = contato.username.lower()
                        if username:
                            if username in dest or dest in Id or dest in nome.lower():
                                dest = nome
                                flag = False
                                break
                        else:
                            if dest in Id or dest in nome.lower():
                                dest = nome
                                flag = False
                                break
                except:
                    pass

                try:
                    if flag:
                        Dialogos = app.iter_dialogs()
                        for dialogo in Dialogos:
                            Id = f"{dialogo.chat.id}"
                            if dialogo.chat.title:
                                nome = f"{dialogo.chat.title}"
                            else:
                                nome = f"{dialogo.chat.first_name}"
                                if dialogo.chat.last_name:
                                    nome += f" {dialogo.chat.last_name}"

                            username = dialogo.chat.username
                            if username:
                                if username in dest or dest in Id or dest in nome.lower():
                                    dest = nome
                                    flag = False
                                    break
                            else:
                                if dest in Id or dest in nome.lower():
                                    dest = nome
                                    flag = False
                                    break
                except:
                    flag = False
                    try:
                        if re.match("^([0-9-]+)$", dest):
                            dest = int(dest)
                        chat = app.get_chat(dest)
                        Id = "{}".format(chat.id)

                        if chat.title:
                            dest = f"{chat.title}"
                        else:
                            dest = f"{chat.first_name}"
                            if chat.last_name:
                                dest += f" {chat.last_name}"

                    except Exception as msg:
                        # print(msg.args[0])
                        log.writelog(f'{msg.args[0]}', arqLog, "ERROR")
                        exit()

            Id = int(Id)
            sendMsg = """{}{}\n{}""".format(saudacao.format(dest), sys.argv[2], msg)
            if re.search("(0|3)", itemType):
                try:
                    graph = '{0}/{1}.png'.format(graph_path, itemid)
                    with open(graph, 'wb') as png:
                        png.write(get_graph.content)
                except BaseException as e:
                    log.writelog('{1} >> An error occurred at save graph file in {0} | Ocorreu um erro ao salvar o grafico no diretório {0}'.format(graph_path, str(e)), arqLog, "WARNING")
                    logout_api()
                    exit()

                try:
                    app.send_photo(Id, graph, caption=sendMsg, parse_mode="html")
                    # print('Telegram sent photo message successfully | Telegram com gráfico enviado com sucesso ({0})'.format(dest))
                    log.writelog('Telegram sent photo message successfully | Telegram com gráfico enviado com sucesso ({0})'.format(dest), arqLog, "INFO")
                except Exception as e:
                    # print('Telegram FAIL at sending photo message | FALHA ao enviar mensagem com gráfico pelo telegram\n%s' % e)
                    log.writelog('{0} >> Telegram FAIL at sending photo message | FALHA ao enviar mensagem com gráfico pelo telegram ({1})'.format(e, dest), arqLog, "ERROR")
                    logout_api()
                    exit()

                try:
                    os.remove(graph)
                except Exception as e:
                    # print(e)
                    log.writelog('{0}'.format(str(e)), arqLog, "ERROR")

            else:
                try:
                    app.send_message(Id, sendMsg, parse_mode="html")
                    # print('Telegram sent successfully | Telegram enviado com sucesso ({0})'.format(dest))
                    log.writelog('Telegram sent successfully | Telegram enviado com sucesso ({0})'.format(dest), arqLog, "INFO")
                except Exception as e:
                    # print('Telegram FAIL at sending photo message | FALHA ao enviar a mensagem com gráfico pelo telegram\n%s' % e)
                    log.writelog('{0} >> Telegram FAIL at sending message | FALHA ao enviar a mensagem pelo telegram ({1})'.format(e, dest), arqLog, "ERROR")
                    logout_api()
                    exit()

    if re.search("(sim|s|yes|y)", str(Ack).lower()):
        if nograph not in argvs:
            ack(dest, "Telegram enviado com sucesso ({0})")

def send_whatsapp(Ldestiny, itemType, get_graph, key):
    line0 = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionWhatsApp', 'line')
    acessKey0 = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionWhatsApp', 'acess.key')
    port0 = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionWhatsApp', 'port')

    try:
       line = decrypt(key, line0)
    except:
       line = line0

    try:
        acessKey = decrypt(key, acessKey0)
    except:
        acessKey = acessKey0

    try:
        port = decrypt(key, port0)
    except:
        port = port0


    saudacao = salutation
    Saudacao = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionWhatsApp', 'salutation.whatsapp')

    if re.search("(sim|s|yes|y)", str(Saudacao).lower()):
        if saudacao:
            saudacao = salutation + ".\\n\\n"
    else:
        saudacao = ""

    msg0 = body.replace("\r", "").split('\n ')[0].replace("\n", "\\n")
    msg = "{}\\n{}".format(sys.argv[2].replace(r"✅", r"\u2705"), msg0)
    message0 = "{}{}".format(saudacao, msg)

    valida = 0
    message1 = ""
    formatter = [("b", "*"), ("i", "_"), ("u", "")]
    for f in formatter:
        old, new = f
        if re.search(r"(<(/)?{}>)".format(old), message0):
            message1 = re.sub(r"(<(/)?{}>)".format(old), r"{}".format(new), message0)
            valida += 1

    if valida == 0:
        message1 = message0

    message = quote(base64.b64encode(message1.encode("utf-8")))
    for destiny in Ldestiny:
        if re.search("(0|3)", itemType):
            Graph = quote(base64.b64encode(get_graph.content))
            try:
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                payload = 'app=NetiZap%20Consumers%201.0&key={key}&text={text}&type=PNG&stream={stream}&filename=grafico'.format(key=acessKey, text=message, stream=Graph)
                url = "http://api.meuaplicativo.vip:{port}/services/file_send?line={line}&destiny={destiny}".format(port=port, line=line, destiny=destiny)
                result = requests.post(url, auth=("user", "api"), headers=headers, data=payload)

                if result.status_code != 200:
                    error = json.loads(result.content.decode("utf-8"))['errors'][0]['message']
                    # error = result.content.decode("utf-8")
                    log.writelog('{0}'.format(error), arqLog, "ERROR")
                    # print('WhatsApp FAIL at sending photo message | FALHA ao enviar mensagem com gráfico pelo WhatsApp\n%s' % error)
                else:
                    # print('WhatsApp sent photo message successfully | WhatsApp com gráfico enviado com sucesso ({0})'.format(destiny))
                    log.writelog('WhatsApp sent photo message successfully | WhatsApp com gráfico enviado com sucesso ({0})'.format(destiny), arqLog, "INFO")
                    log.writelog('{0}'.format(json.loads(result.text)["result"]), arqLog, "INFO")

            except Exception as e:
                # print(e)
                log.writelog('{0}'.format(str(e)), arqLog, "ERROR")
                exit()
        else:
            try:
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                payload = 'App=NetiZap%20Consumers%201.0&AccessKey={}'.format(acessKey)
                url = "http://api.meuaplicativo.vip:{port}/services/message_send?line={line}&destiny={destiny}&reference&text={text}".format(port=port, line=line, destiny=destiny, text=message)
                result = requests.post(url, auth=("user", "api"), headers=headers, data=payload)

                if result.status_code != 200:
                    error = json.loads(result.content.decode("utf-8"))['errors'][0]['message']
                    # error = result.content.decode("utf-8")
                    log.writelog('{0}'.format(error), arqLog, "ERROR")
                    # print('WhatsApp FAIL at sending message | FALHA ao enviar a mensagem pelo WhatsApp\n%s' % error)

                else:
                    # print('WhatsApp sent successfully | WhatsApp enviado com sucesso ({0})'.format(destiny))
                    log.writelog('WhatsApp sent successfully | WhatsApp enviado com sucesso ({0})'.format(destiny), arqLog, "INFO")
                    log.writelog('{0}'.format(json.loads(result.text)["result"]), arqLog, "INFO")

            except Exception as e:
                # print(e)
                log.writelog('{0}'.format(str(e)), arqLog, "ERROR")
                exit()

    if re.search("(sim|s|yes|y)", str(Ack).lower()):
        if nograph not in argvs:
            ack(destiny, "WhatsApp enviado com sucesso ({0})")

def token():
    try:
        login_api = requests.post(f'{zbx_server}/api_jsonrpc.php', headers={'Content-type': 'application/json'},
            verify=False, data=json.dumps(
                {
                  "jsonrpc": "2.0",
                  "method": "user.login",
                  "params": {
                      "user": zbx_user,
                      "password": zbx_pass
                  },
                  "id": 1
                }
            )
        )

        login_api = json.loads(login_api.text.encode('utf-8'))

        if 'result' in login_api:
            auth = login_api["result"]
            return auth

        elif 'error' in login_api:
            # print('Zabbix: %s' % login_api["error"]["data"])
            log.writelog('Zabbix: {0}'.format(login_api["error"]["data"]), arqLog, "ERROR")
            exit()
        else:
            # print(login_api)
            log.writelog('{0}'.format(login_api), arqLog, "ERROR")
            exit()

    except ValueError as e:
        # print('Check declared zabbix URL/IP and try again | Valide a URL/IP do Zabbix declarada e tente novamente\nCurrent: %s' % zbx_server)
        log.writelog('Check declared zabbix URL/IP and try again | Valide a URL/IP do Zabbix declarada e tente novamente. (Current: {0})'.format(zbx_server), arqLog, "WARNING")
        exit()
    except Exception as e:
        # print(e)
        log.writelog('{0}'.format(str(e)), arqLog, "WARNING")
        exit()

def version_api():
    resultado = requests.post(f'{zbx_server}/api_jsonrpc.php', headers={'Content-type': 'application/json'},
        verify=False, data=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": "apiinfo.version",
                    "params": [],
                    "id": 5
                }
        )
    )
    resultado = json.loads(resultado.content)
    if 'result' in resultado:
        resultado = resultado["result"]
    return resultado

def logout_api():
    requests.post(f'{zbx_server}/api_jsonrpc.php', headers={'Content-type': 'application/json'},
        verify=False, data=json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "user.logout",
                "params": [],
                "auth": auth,
                "id": 4
            }
        )
    )

def getgraph(itemname, period):
    stime = int(PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSection', 'stime'))  # Graph start time [3600 = 1 hour ago]  |  Hora inicial do grafico [3600 = 1 hora atras]
    try:
        loginpage = requests.get(f'{zbx_server}/index.php', auth=(zbx_user, zbx_pass), verify=False).text
        enter = re.search('<button.*value=".*>(.*?)</button>', loginpage)
        s = requests.Session()

        try:
            enter = str(enter.group(1))
            s.post(f'{zbx_server}/index.php?login=1', params={'name': zbx_user, 'password': zbx_pass, 'enter': enter}, verify=False).text
        except:
           pass

        stime = time.strftime("%Y%m%d%H%M%S", time.localtime(time.time() - stime))

        if 4.0 > float(version_api()[:3]):
            period = "period={0}".format(period)
        else:
            periodD = period // 86400
            segundos_rest = period % 86400
            periodH = segundos_rest // 3600
            segundos_rest = segundos_rest % 3600
            periodM = segundos_rest // 60
            periodS = segundos_rest % 60

            if periodD > 0:
                period = "from=now-{0}d-{1}h-{2}m&to=now".format(periodD, periodH, periodM)
                itemname = "{0} ({1}d {2}h:{3}m)".format(itemname, periodD, periodH, periodM)

            elif periodD == 0 and periodH == 0:
                period = "from=now-{0}m&to=now".format(periodM)
                itemname = "{0} ({1}m)".format(itemname, periodM)

            elif periodD == 0 and period % 60 == 0:
                period = "from=now-{0}h&to=now".format(periodH)
                itemname = "{0} ({1}h)".format(itemname, periodH)

            else:
                period = "from=now-{0}h-{1}m&to=now".format(periodH, periodM)
                itemname = "{0} ({1}h:{2}m)".format(itemname, periodH, periodM)

        get_graph = s.get('{0}/chart3.php?name={1}&{2}&width={3}&height={4}&stime={5}&items[0][itemid]={6}&items[0][drawtype]=5&items[0][color]={7}'.format(
            zbx_server, itemname, period, width, height, stime, itemid, color))

        sid = s.cookies.items()[0][1]
        s.post('{0}/index.php?reconnect=1&sid={1}'.format(zbx_server, sid))

        return get_graph

    except BaseException:
        log.writelog('Can\'t connect to {0}/index.php | Não foi possível conectar-se à {0}/index.php'.format(zbx_server), arqLog, "CRITICAL")
        logout_api()
        exit()

def getItemType(itemid):
    itemtype_api = requests.post(f'{zbx_server}/api_jsonrpc.php', headers={'Content-type': 'application/json'},
                                 verify=False, data=json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "item.get",
                "params": {
                    "output": ["value_type"], "itemids": itemid, "webitems": itemid
                },
                "auth": auth,
                "id": 2
            }
        )
     )

    itemtype_api = json.loads(itemtype_api.text.encode('utf-8'))

    if itemtype_api["result"]:
        item_type = itemtype_api["result"][0]['value_type']
        return item_type
    else:
        log.writelog(
            'Invalid ItemID or user has no read permission on item/host | ItemID inválido ou usuário sem permissão de leitura no item/host',
            arqLog, "WARNING")
        logout_api()
        exit()

def ack(dest, message):
    Json = {
            "jsonrpc": "2.0",
            "method": "event.acknowledge",
            "params": {
                "eventids": eventid,
                "message":  message.format(dest)
            },
            "auth": auth,
            "id": 3
    }
    if 4.0 < float(version_api()[:3]):
        Json["params"]["action"] = 6

    requests.post(f'{zbx_server}/api_jsonrpc.php', headers={'Content-type': 'application/json'}, verify=False,
            data=json.dumps(Json))

def get_cripto():
    with open(fileX, 'r') as f:
        return json.load(f)

def decrypt(key, source, decode=True):
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    if decode:
        source = base64.b64decode(source.encode("ISO-8859-1"))
    key = SHA256.new(key.encode("ISO-8859-1")).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding].decode("ISO-8859-1")  # remove the padding

def main():
    codDDI = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionWhatsApp', 'cod.ddi')
    if nograph not in argvs:
        item_type = getItemType(itemid)
        get_graph = getgraph(itemname, period)
    else:
        item_type = "1"
        get_graph = ""

    dest = sys.argv[1]
    destino = destinatarios(dest)

    codeKey = JSON['code']

    emails = []
    telegrams = []
    whatsapps = []

    for x in destino:
        if re.match(f"^{codDDI}\d{8}.*$", x):
            whatsapps.append(x)

        elif re.search("^.*@[a-z0-9]+\.[a-z]+(\.[a-z].*)?$", x.lower()):
            emails.append(x)

        else:
            telegram = x.replace("_", " ")
            telegrams.append(telegram)

    if [] != whatsapps:
        send_whatsapp(whatsapps, item_type, get_graph, codeKey)

    if [] != telegrams:
        send_telegram(telegrams, item_type, get_graph, codeKey)

    if [] != emails:
        send_mail(emails, item_type, get_graph, codeKey)

if __name__ == '__main__':
    JSON = get_cripto()
    auth = token()
    main()
    logout_api()
