## lazymux.py - Lazymux v4.0
##
import os, sys
import readline
from time import sleep as timeout
from core.lzmcore import *

def main():
    
	banner()
	print("   [01] Recopilación de información")
	print("   [02] analizador de vunerabilidades")
	print("   [03] Piratería web")
	print("   [04] Evaluación de la base de datos")
	print("   [05] ataque a contraseñas")
	print("   [06] ataque inalámbrico")
	print("   [07] Ingeniería inversa")
	print("   [08] herramientas de explotación")
	print("   [09] Olfatear y suplantar")
	print("   [10] Herramientas de informes")
	print("   [11] Herramientas forenses")
	print("   [12] Pruebas de estrés")
	print("   [13] instalar Linux Distro")
	print("   [14] utilidad termux")
	print("   [15] Función de shell [.bashrc]")
	print("   [16] Instalar juegos CLI")
	print("   [17] analizador de malware")
	print("   [18] Compiladora / Intérprete")
	print("   [19] Herramientas de ingeniería social")
	print("\n   [00]salir de lazmux\n")
	lazymux = input("lzmx > set_install ")

	# 01 - I
	if lazymux.strip() == "1" or lazymux.strip() == "01":
		print("\n    [01] Nmap: utilidad para el descubrimiento de redes y la auditoría de seguridad")
		print("    [02] Red Hawk: recopilación de información, escaneo y rastreo de vulnerabilidades")
		print("    [03] D-TECT: herramienta todo en uno para pruebas de penetración")
		print("    [04] sqlmap: Inyección automática de SQL y herramienta de adquisición de bases de datos")
		print("    [05] Infoga: herramienta para recopilar información de cuentas de correo electrónico")
		print("    [06] ReconDog: herramienta de análisis de vulnerabilidades y recopilación de información")
		print("    [07] AndroZenmap")
		print("    [08] sqlmate: un amigo de SQLmap que hará lo que siempre esperó de SQLmap")
		print("    [09] AstraNmap: escáner de seguridad utilizado para encontrar hosts y servicios en una red informática")
		print("    [10] MapEye: Rastreador de ubicación GPS preciso (teléfonos Android, IOS, Windows)")
		print("    [11] Easymap: acceso directo a Nmap")
		print("    [12] BlackBox: un marco de pruebas de penetración")
		print("    [13]XD3v: Potente herramienta que le permite conocer todos los detalles esenciales sobre su teléfono")
		print("    [14] Crips: esta herramienta es una colección de herramientas de IP en línea que se pueden utilizar para obtener información rápidamente sobre direcciones IP, páginas web y registros DNS.")
		print("    [15] SIR: Resuelve desde la red la última ip conocida de un nombre de Skype")
		print("    [16] EvilURL: Genere dominios malvados Unicode para IDN Homograph Attack y detectelos")
		print("    [17] Striker: Recon & Vulnerability Scanning Suite")
		print("    [18] Xshell: Kit de herramientas")
		print("    [19] OWScan: Escáner web OVID")
		print("    [20] OSIF: Facebook de información de código abierto")
		print("    [21] Devploit: herramienta de recopilación de información simple")
		print("    [22] Namechk: herramienta de Osint basada en namechk.com para comprobar los nombres de usuario en más de 100 sitios web, foros y redes sociales")
		print("    [23] AUXILE: Marco de análisis de aplicaciones web")
		print("    [24] inther: recopilación de información mediante shodan, censys y hackertgeart")
		print("    [25] GINF: herramienta de recopilación de información de GitHub")
		print("    [26] Seguimiento GPS")
		print("    [27] ASU: Kit de herramientas de piratería de Facebook")
		print("    [28] fin: Descargador de imágenes de Facebook")
		print("    [29] MaxSubdoFinder: herramienta para descubrir subdominios")
		print("    [30] pwnedOrNot: herramienta OSINT para encontrar contraseñas de cuentas de correo electrónico comprometidas")
		print("    [31] Mac-Lookup: busca información sobre una dirección Mac en particular")
		print("    [32] BillCipher: herramienta de recopilación de información para un sitio web o una dirección IP")
		print("    [33] dnsrecon: evaluación de seguridad y resolución de problemas de red")
		print("    [34] zphisher: herramienta automatizada de phishing")
		print("    [35] Mr.SIP: herramienta de auditoría y ataque basada en SIP")
		print("    [36] Sherlock: busca cuentas de redes sociales por nombre de usuario")
		print("    [37] userrecon: encuentre nombres de usuario en más de 75 redes sociales")
		print("    [38] PhoneInfoga: una de las herramientas más avanzadas para escanear números de teléfono utilizando solo recursos gratuitos")
		print("    [39] SiteBroker: una utilidad multiplataforma basada en Python para la recopilación de información y la automatización de pruebas de penetración")
		print("    [40] maigret: recopile un expediente sobre una persona por nombre de usuario de miles de sitios")
		print("    [41] GatheTOOL: Recopilación de información - API hackertarget.com")
		print("    [42] Kit de herramientas ADB")
		print("    [43] TekDefense-Automater: máquinas expendedoras - IP URL and MD5 OSINT Analysis")
		print("    [44] EagleEye: acecha a tus amigos. Encuentre sus perfiles de Instagram, FB y Twitter mediante el reconocimiento de imágenes y la búsqueda inversa de imágenes")
		print("    [45] EyeWitness: EyeWitness está diseñado para tomar capturas de pantalla de sitios web, proporcionar información del encabezado del servidor e identificar las credenciales predeterminadas, si es posible")
		print("    [46] InSpy: una herramienta de enumeración de LinkedIn basada en python")
		print("    [47] Filtrado: ¿Filtrado? 2.1 - Una herramienta de verificación de códigos hash, contraseñas y correos electrónicos filtrados")
		print("\n    [00] salir al menu\n")
		infogathering = input("lzmx > set_install ")
		if infogathering == "@":
			infogathering = ""
			for x in range(1,201):
				infogathering += f"{x} "
		if len(infogathering.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for infox in infogathering.split():
			if infox.strip() == "01" or infox.strip() == "1": nmap()
			elif infox.strip() == "02" or infox.strip() == "2": red_hawk()
			elif infox.strip() == "03" or infox.strip() == "3": dtect()
			elif infox.strip() == "04" or infox.strip() == "4": sqlmap()
			elif infox.strip() == "05" or infox.strip() == "5": infoga()
			elif infox.strip() == "06" or infox.strip() == "6": reconDog()
			elif infox.strip() == "07" or infox.strip() == "7": androZenmap()
			elif infox.strip() == "08" or infox.strip() == "8": sqlmate()
			elif infox.strip() == "09" or infox.strip() == "9": astraNmap()
			elif infox.strip() == "10": mapeye()
			elif infox.strip() == "11": easyMap()
			elif infox.strip() == "12": blackbox()
			elif infox.strip() == "13": xd3v()
			elif infox.strip() == "14": crips()
			elif infox.strip() == "15": sir()
			elif infox.strip() == "16": evilURL()
			elif infox.strip() == "17": striker()
			elif infox.strip() == "18": xshell()
			elif infox.strip() == "19": owscan()
			elif infox.strip() == "20": osif()
			elif infox.strip() == "21": devploit()
			elif infox.strip() == "22": namechk()
			elif infox.strip() == "23": auxile()
			elif infox.strip() == "24": inther()
			elif infox.strip() == "25": ginf()
			elif infox.strip() == "26": gpstr()
			elif infox.strip() == "27": asu()
			elif infox.strip() == "28": fim()
			elif infox.strip() == "29": maxsubdofinder()
			elif infox.strip() == "30": pwnedornot()
			elif infox.strip() == "31": maclook()
			elif infox.strip() == "32": billcypher()
			elif infox.strip() == "33": dnsrecon()
			elif infox.strip() == "34": zphisher()
			elif infox.strip() == "35": mrsip()
			elif infox.strip() == "36": sherlock()
			elif infox.strip() == "37": userrecon()
			elif infox.strip() == "38": phoneinfoga()
			elif infox.strip() == "39": sitebroker()
			elif infox.strip() == "40": maigret()
			elif infox.strip() == "41": gathetool()
			elif infox.strip() == "42": adbtk()
			elif infox.strip() == "43": tekdefense()
			elif infox.strip() == "44": eagleeye()
			elif infox.strip() == "45": eyewitness()
			elif infox.strip() == "46": inspy()
			elif infox.strip() == "47": leaked()
			elif infox.strip() == "00" or infox.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	
	# 02 - Vulnerability Analysis
	elif lazymux.strip() == "2" or lazymux.strip() == "02":
		print("\n    [01] Nmap: utilidad para el descubrimiento de redes y la auditoría de seguridad")
		print("    [02] AndroZenmap")
		print("    [03] AstraNmap: escáner de seguridad utilizado para encontrar hosts y servicios en una red informática")
		print("    [04] Easymap: acceso directo a Nmap")
		print("    [05] Red Hawk: recopilación de información, escaneo y rastreo de vulnerabilidades")
		print("    [06] D-TECT: herramienta todo en uno para pruebas de penetración")
		print("    [07] Damn Small SQLi Scanner: A fully functional SQL injection vulnerability scanner (supporting GET and POST parameters) written in under 100 lines of code")
		print("    [08] SQLiv: escáner de vulnerabilidad de inyección SQL masiva")
		print("    [09] sqlmap: Inyección automática de SQL y herramienta de adquisición de bases de datos")
		print("    [10] sqlscan: Escáner de SQL rápido, Dorker, inyector de Webshell PHP")
		print("    [11] Wordpresscan: WPScan reescrito en Python + algunas ideas de WPSeku")
		print("    [12] WPScan: escáner de seguridad gratuito de wordPress")
		print("    [13] sqlmate: un amigo de SQLmap que hará lo que siempre esperó de SQLmap")
		print("    [14] termux-wordpresscan")
		print("    [15] TM-scanner: escáner de vulnerabilidades de sitios web para termux")
		print("    [16] Rang3r: Escáner de puerto + IP de subprocesos múltiples")
		print("    [17] Striker: Recon & Vulnerability Scanning Suite")
		print("    [18] Routersploit: Marco de explotación para dispositivos integrados")
		print("    [19] Xshell: Kit de herramientas")
		print("    [20] SH33LL: Escáner de Shell")
		print("    [21] BlackBox: un marco de pruebas de penetración")
		print("    [22] XAttacker: explorador de vulnerabilidades de sitios web y explorador automático")
		print("    [23] OWScan: Escáner web OVID")
		print("    [24] XPL-SEARCH: busque exploits en múltiples bases de datos de exploits")
		print("    [25] AndroBugs_Framework: un eficiente escáner de vulnerabilidades de Android que ayuda a los desarrolladores o piratas informáticos a encontrar posibles vulnerabilidades de seguridad en las aplicaciones de Android")
		print("    [26] Clickjacking-Tester: un script de Python diseñado para verificar si el sitio web es vulnerable al clickjacking y crear un poc")
		print("    [27] Sn1per: plataforma de gestión de superficie de ataque | Sn1perSecurity LLC")
		print("\n  [00] salir al menu\n")
		vulnsys = input("lzmx > set_install ")
		if vulnsys == "@":
			vulnsys = ""
			for x in range(1,201):
				vulnsys += f"{x} "
		if len(vulnsys.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for vulnx in vulnsys.split():
			if vulnsys.strip() == "01" or vulnsys.strip() == "1": nmap()
			elif vulnsys.strip() == "02" or vulnsys.strip() == "2": androZenmap()
			elif vulnsys.strip() == "03" or vulnsys.strip() == "3": astraNmap()
			elif vulnsys.strip() == "04" or vulnsys.strip() == "4": easyMap()
			elif vulnsys.strip() == "05" or vulnsys.strip() == "5": red_hawk()
			elif vulnsys.strip() == "06" or vulnsys.strip() == "6": dtect()
			elif vulnsys.strip() == "07" or vulnsys.strip() == "7": dsss()
			elif vulnsys.strip() == "08" or vulnsys.strip() == "8": sqliv()
			elif vulnsys.strip() == "09" or vulnsys.strip() == "9": sqlmap()
			elif vulnsys.strip() == "10": sqlscan()
			elif vulnsys.strip() == "11": wordpreSScan()
			elif vulnsys.strip() == "12": wpscan()
			elif vulnsys.strip() == "13": sqlmate()
			elif vulnsys.strip() == "14": wordpresscan()
			elif vulnsys.strip() == "15": tmscanner()
			elif vulnsys.strip() == "16": rang3r()
			elif vulnsys.strip() == "17": striker()
			elif vulnsys.strip() == "18": routersploit()
			elif vulnsys.strip() == "19": xshell()
			elif vulnsys.strip() == "20": sh33ll()
			elif vulnsys.strip() == "21": blackbox()
			elif vulnsys.strip() == "22": xattacker()
			elif vulnsys.strip() == "23": owscan()
			elif vulnsys.strip() == "24": xplsearch()
			elif vulnsys.strip() == "25": androbugs()
			elif vulnsys.strip() == "26": clickjacking()
			elif vulnsys.strip() == "27": sn1per()
			elif vulnsys.strip() == "00" or vulnsys.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)

	# 03 - Web Hacking
	elif lazymux.strip() == "3" or lazymux.strip() == "03":
		print("\n  [01] sqlmap: Inyección automática de SQL y herramienta de adquisición de bases de datos")
		print("    [02] WebDAV: explorador de carga de archivos WebDAV")
		print("    [03] MabdoFinder: herramienta para descubrir subdominios")
		print("    [04] Webdav Mass ExploitxSu")
		print("    [05] Atlas: Sugerencia rápida de manipulación de SQLMap")
		print("    [06] mysqldump: volcar sitios de resultados sql con easy")
		print("    [07] Websploit: un marco avanzado de MiTM")
		print("    [08] sqlmate: un amigo de SQLmap que hará lo que siempre esperó de SQLmap")
		print("    [09] inther: recopilación de información mediante shodan, censys y hackertarget") 
		print("    [10] HPB: Generador de páginas HTML")
		print("    [11] Xshell: Kit de herramientas")
		print("    [12] SH33LL: Escáner de  Shell")
		print("    [13] XAttacker: explorador de vulnerabilidades de sitios web y explorador automático")
		print("    [14] XSStrike: los escáneres XS más avanzados")
		print("    [15] Breacher: un buscador avanzado de panel de administración multiproceso")
		print("    [16] OWScan: Escáner web OVID")
		print("    [17] ko-dork: un simple escáner web de vulnerabilidades")
		print("    [18] ApSca: potente aplicación de penetración web")
		print("    [19] amox: encuentra una puerta trasera o un caparazón plantado en un sitio mediante un ataque de diccionario")
		print("    [20] FaDe: desfiguración falsa con kindeditor, fckeditor y webdav")
		print("    [21] AUXILIAR: Marco auxiliar")
		print("    [22] xss-payload-list: Cross Site Scripting ( XSS ) Vulnerability Payload List")
		print("    [23] Xadmin: Buscador del panel de administración")
		print("    [24] CMSeeK: paquete de detección y explotación de CMS: escanee WordPress, Joomla, Drupal y más de 180 CMS")
		print("    [25] CMSmap: un escáner CMS de código abierto de Python que automatiza el proceso de detección de fallas de seguridad de los CMS más populares")
		print("    [26] CrawlBox: una forma sencilla de acceder al directorio web mediante fuerza bruta")
		print("    [27] LFISuite: explorador LFI totalmente automático (+ shell inverso) y escáner")
		print("    [28] Parsero: herramienta de auditoría Robots.txt")
		print("    [29] Sn1per: plataforma de gestión de superficie de ataque | Sn1perSecurity LLC")
		print("    [30] Sublist3r: herramienta de enumeración rápida de subdominios para probadores de penetración")
		print("    [31] WP-plugin-scanner: una herramienta para enumerar los complementos instalados en un sitio web impulsado por wordpress")
		print("    [32] WhatWeb: escáner web de próxima generación")
		print("\n    [00] salir al menu\n")
		webhack = input("lzmx > set_install ")
		if webhack == "@":
			webhack = ""
			for x in range(1,201):
				webhack += f"{x} "
		if len(webhack.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for webhx in webhack.split():
			if webhx.strip() == "01" or webhx.strip() == "1": sqlmap()
			elif webhx.strip() == "02" or webhx.strip() == "2": webdav()
			elif webhx.strip() == "03" or webhx.strip() == "3": maxsubdofinder()
			elif webhx.strip() == "04" or webhx.strip() == "4": webmassploit()
			elif webhx.strip() == "05" or webhx.strip() == "5": atlas()
			elif webhx.strip() == "06" or webhx.strip() == "6": sqldump()
			elif webhx.strip() == "07" or webhx.strip() == "7": websploit()
			elif webhx.strip() == "08" or webhx.strip() == "8": sqlmate()
			elif webhx.strip() == "09" or webhx.strip() == "9": inther()
			elif webhx.strip() == "10": hpb()
			elif webhx.strip() == "11": xshell()
			elif webhx.strip() == "12": sh33ll()
			elif webhx.strip() == "13": xattacker()
			elif webhx.strip() == "14": xsstrike()
			elif webhx.strip() == "15": breacher()
			elif webhx.strip() == "16": owscan()
			elif webhx.strip() == "17": kodork()
			elif webhx.strip() == "18": apsca()
			elif webhx.strip() == "19": amox()
			elif webhx.strip() == "20": fade()
			elif webhx.strip() == "21": auxile()
			elif webhx.strip() == "22": xss_payload_list()
			elif webhx.strip() == "23": xadmin()
			elif webhx.strip() == "24": cmseek()
			elif webhx.strip() == "25": cmsmap()
			elif webhx.strip() == "26": crawlbox()
			elif webhx.strip() == "27": lfisuite()
			elif webhx.strip() == "28": parsero()
			elif webhx.strip() == "29": sn1per()
			elif webhx.strip() == "30": sublist3r()
			elif webhx.strip() == "31": wppluginscanner()
			elif webhx.strip() == "32": whatweb()
			elif webhx.strip() == "00" or webhx.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	
	# 04 - Database Assessment
	elif lazymux.strip() == "4" or lazymux.strip() == "04":
		print("\n    [01] DbDat: DbDat realiza numerosas comprobaciones en una base de datos para evaluar la seguridad")
		print("    [02] sqlmap: Inyección automática de SQL y herramienta de adquisición de bases de datos")
		print("    [03] NoSQLMap: herramienta automatizada de enumeración de bases de datos NoSQL y explotación de aplicaciones web")
		print("    [04] audit_couchdb: detecta problemas de seguridad, grandes o pequeños, en un servidor CouchDB")
		print("    [05] mongoaudit: una herramienta automatizada de pentesting que le permite saber si sus instancias de MongoDB están protegidas correctamente")
		print("\n    [00] salir al menu\n")
		dbssm = input("lzmx > set_install ")
		if dbssm == "@":
			dbssm = ""
			for x in range(1,201):
				dbssm += f"{x} "
		if len(dbssm.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for dbsx in dbssm.split():
			if dbsx.strip() == "01" or dbsx.strip() == "1": dbdat()
			elif dbsx.strip() == "02" or dbsx.strip() == "2": sqlmap()
			elif dbsx.strip() == "03" or dbsx.strip() == "3": nosqlmap
			elif dbsx.strip() == "04" or dbsx.strip() == "4": audit_couchdb()
			elif dbsx.strip() == "05" or dbsx.strip() == "5": mongoaudit()
			elif dbsx.strip() == "00" or dbsx.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	
	# 05 - Password Attacks
	elif lazymux.strip() == "5" or lazymux.strip() == "05":
		print("\n    [01] Hydra: Cracker de inicio de sesión de red que admite diferentes servicios")
		print("    [02] FMBrute: Facebook Multi Brute Force")
		print("    [03] HashID: Software para identificar los diferentes tipos de hashes")
		print("    [04] Fuerza bruta 3 de Facebook")
		print("    [05] Black Hydra: un pequeño programa para acortar las sesiones de fuerza bruta en hydra")
		print("    [06] Hash Buster: descifra hashes en segundos")
		print("    [07] FBBrute: Fuerza bruta de Facebook")
		print("    [08] Cupp: Generador de perfiles de contraseñas de usuario común")
		print("    [09] InstaHack: fuerza bruta de Instagram")
		print("    [10] Lista de palabras en indonesio")
		print("    [11] Xshell")
		print("    [12] Aircrack-ng: conjunto de herramientas de auditoría de seguridad WiFi")
		print("    [13] BlackBox: un marco de pruebas de penetración")
		print("    [14] Katak: un juego de herramientas de fuerza bruta de inicio de sesión de software de código abierto y descifrador de hash")
		print("    [15] Hasher: cracker de hash con detección automática de hash")
		print("    [16] Hash-Generator: Beautiful Hash Generator")
		print("    [17] nk26: Codificación Nkosec")
		print("    [18] Hasherdotid: una herramienta para encontrar un texto cifrado")
		print("    [19] Crunch: generador de listas de palabras altamente personalizable")
		print("    [20] Hashcat: la utilidad de recuperación de contraseñas más rápida y avanzada del mundo")
		print("    [21] ASU: Kit de herramientas de piratería de Facebook")
		print("    [22] Credmap: una herramienta de código abierto que se creó para crear conciencia sobre los peligros de la reutilización de credenciales")
		print("    [23] BruteX: fuerza bruta automáticamente todos los servicios que se ejecutan en un objetivo")
		print("    [24] Gemail-Hack: script de Python para Hackear la fuerza bruta de la cuenta de gmail")
		print("    [25] GoblinWordGenerator: generador de listas de palabras de Python")
		print("    [26] PyBozoCrack: un cracker MD5 tonto y efectivo en Python")
		print("    [27] brutespray: Fuerza bruta desde la salida de Nmap: intenta automáticamente los créditos predeterminados en los servicios encontrados")
		print("\n    [00] salir al menu\n")
		passtak = input("lzmx > set_install ")
		if passtak == "@":
			passtak = ""
			for x in range(1,201):
				passtak += f"{x} "
		if len(passtak.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for passx in passtak.split():
			if passx.strip() == "01" or passx.strip() == "1": hydra()
			elif passx.strip() == "02" or passx.strip() == "2": fmbrute()
			elif passx.strip() == "03" or passx.strip() == "3": hashid()
			elif passx.strip() == "04" or passx.strip() == "4": fbBrute()
			elif passx.strip() == "05" or passx.strip() == "5": black_hydra()
			elif passx.strip() == "06" or passx.strip() == "6": hash_buster()
			elif passx.strip() == "07" or passx.strip() == "7": fbbrutex()
			elif passx.strip() == "08" or passx.strip() == "8": cupp()
			elif passx.strip() == "09" or passx.strip() == "9": instaHack()
			elif passx.strip() == "10": indonesian_wordlist()
			elif passx.strip() == "11": xshell()
			elif passx.strip() == "12": aircrackng()
			elif passx.strip() == "13": blackbox()
			elif passx.strip() == "14": katak()
			elif passx.strip() == "15": hasher()
			elif passx.strip() == "16": hashgenerator()
			elif passx.strip() == "17": nk26()
			elif passx.strip() == "18": hasherdotid()
			elif passx.strip() == "19": crunch()
			elif passx.strip() == "20": hashcat()
			elif passx.strip() == "21": asu()
			elif passx.strip() == "22": credmap()
			elif passx.strip() == "23": brutex()
			elif passx.strip() == "24": gemailhack()
			elif passx.strip() == "25": goblinwordgenerator()
			elif passx.strip() == "26": pybozocrack()
			elif passx.strip() == "27": brutespray()
			elif passx.strip() == "00" or passx.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	
	# 06 - Wireless Attacks
	elif lazymux.strip() == "6" or lazymux.strip() == "06":
		print("\n    [01] Aircrack: conjunto de herramientas de auditoría de seguridad WiFi")
		print("    [02] Wifite: una herramienta automatizada de ataque inalámbrico")
		print("    [03] Wifiphisher: El marco de puntos de acceso no autorizados")
		print("    [04] Routersploit: Marco de explotación para dispositivos integrados")
		print("    [05] PwnSTAR: (Pwn SofT-Ap scRipt) - ¡para todas sus necesidades de AP falsos!")
		print("    [06] Pyrit: el famoso cracker precalculado WPA, migrado de Google")
		print("\n    [00] salir al menu\n")
		wiretak = input("lzmx > set_install ")
		if wiretak == "@":
			wiretak = ""
			for x in range(1,201):
				wiretak += f"{x} "
		if len(wiretak.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for wirex in wiretak.split():
			if wirex.strip() == "01" or wirex.strip() == "1": aircrackng()
			elif wirex.strip() == "02" or wirex.strip() == "2": wifite()
			elif wirex.strip() == "03" or wirex.strip() == "3": wifiphisher()
			elif wirex.strip() == "04" or wirex.strip() == "4": routersploit()
			elif wirex.strip() == "05" or wirex.strip() == "5": pwnstar()
			elif wirex.strip() == "06" or wirex.strip() == "6": pyrit()
			elif wirex.strip() == "00" or wirex.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	
	# 07 - Reverse Engineering
	elif lazymux.strip() == "7" or lazymux.strip() == "07":
		print("\n    [01] Explotación binaria")
		print("    [02] jadx: Decompilador DEX a JAVA")
		print("    [03] apktool: una utilidad que se puede utilizar para aplicaciones de Android de ingeniería inversa")
		print("    [04] descompyle6: descompilador de código de bytes de versiones cruzadas de Python")
		print("    [05] ddcrypt: Desofuscador DroidScript APK")
		print("    [06] CFR: otro descompilador de Java")
		print("    [07] UPX: Packer definitivo para eXecutables")
		print("    [08] pyinstxtractor: Extractor PyInstaller")
		print("    [09] innoextract: una herramienta para descomprimir instaladores creada por Inno Setup")
		print("\n    [00] salir al menu\n")
		reversi = input("lzmx > set_install ")
		if reversi == "@":
			reversi = ""
			for x in range(1,201):
				reversi += f"{x} "
		if len(reversi.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for revex in reversi.split():
			if revex.strip() == "01" or revex.strip() == "1": binploit()
			elif revex.strip() == "02" or revex.strip() == "2": jadx()
			elif revex.strip() == "03" or revex.strip() == "3": apktool()
			elif revex.strip() == "04" or revex.strip() == "4": uncompyle()
			elif revex.strip() == "05" or revex.strip() == "5": ddcrypt()
			elif revex.strip() == "06" or revex.strip() == "6": cfr()
			elif revex.strip() == "07" or revex.strip() == "7": upx()
			elif revex.strip() == "08" or revex.strip() == "8": pyinstxtractor()
			elif revex.strip() == "09" or revex.strip() == "9": innoextract()
			elif revex.strip() == "00" or revex.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	
	# 08 - Exploitation Tools
	elif lazymux.strip() == "8" or lazymux.strip() == "08":
		print("\n    [01] Metasploit: plataforma avanzada de código abierto para desarrollar, probar y usar código de explotación")
		print("    [02] commix: Herramienta automatizada de explotación e inyección de comandos de sistema operativo todo en uno")
		print("    [03] BlackBox: un marco de pruebas de penetración")
		print("    [04] Brutal: Carga útil para pequeñitos como un rubber ducky , pero la sintaxis es diferente")
		print("    [05] TXTool: una sencilla herramienta de pentesting")
		print("    [06] XAttacker: explorador de vulnerabilidades de sitios web y explorador automático")  
		print("    [07] Websploit: un marco avanzado de MiTM")
		print("    [08] Routersploit: Marco de explotación para dispositivos integrados")
		print("    [09] A-Rat: herramienta de administración remota")
		print("    [10] BAF: Marco de ataque ciego")
		print("    [11] Gloom-Framework: Marco de pruebas de penetración de Linux")
		print("    [12] Zerodoor: un script escrito con pereza para generar puertas traseras multiplataforma sobre la marcha:)")
		print("\n    [00] salir al menu\n")
		exploitool = input("lzmx > set_install ")
		if exploitool == "@":
			exploitool = ""
			for x in range(1,201):
				exploitool += f"{x} "
		if len(exploitool.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for explx in exploitool.split():
			if explx.strip() == "01" or explx.strip() == "1": metasploit()
			elif explx.strip() == "02" or explx.strip() == "2": commix()
			elif explx.strip() == "03" or explx.strip() == "3": blackbox()
			elif explx.strip() == "04" or explx.strip() == "4": brutal()
			elif explx.strip() == "05" or explx.strip() == "5": txtool()
			elif explx.strip() == "06" or explx.strip() == "6": xattacker()
			elif explx.strip() == "07" or explx.strip() == "7": websploit()
			elif explx.strip() == "08" or explx.strip() == "8": routersploit()
			elif explx.strip() == "09" or explx.strip() == "9": arat()
			elif explx.strip() == "10": baf()
			elif explx.strip() == "11": gloomframework()
			elif explx.strip() == "12": zerodoor()
			elif explx.strip() == "00" or explx.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	
	# 09 - Sniffing and Spoofing
	elif lazymux.strip() == "9" or lazymux.strip() == "09":
		print("\n    [01] KnockMail: verificar si el correo electrónico existe")
		print("    [02] tcpdump: un potente analizador de paquetes de línea de comandos")
		print("    [03] Ettercap: paquete completo para ataques MITM, puede rastrear conexiones en vivo, filtrar contenido sobre la marcha y mucho más")
		print("    [04] hping3: hping es un ensamblador / analizador de paquetes TCP / IP orientado a la línea de comandos")
		print("    [05] tshark: analizador y rastreador de protocolos de red")
		print("\n    [00] salir al menu\n")
		sspoof = input("lzmx > set_install ")
		if sspoof == "@":
			sspoof = ""
			for x in range(1,201):
				sspoof += f"{x} "
		if len(sspoof.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for sspx in sspoof.split():
			if sspx.strip() == "01" or sspx.strip() == "1": knockmail()
			elif sspx.strip() == "02" or sspx.strip() == "2": tcpdump()
			elif sspx.strip() == "03" or sspx.strip() == "3": ettercap()
			elif sspx.strip() == "04" or sspx.strip() == "4": hping3()
			elif sspx.strip() == "05" or sspx.strip() == "5": tshark()
			elif sspx.strip() == "00" or sspx.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	
	# 10 - Reporting Tools
	elif lazymux.strip() == "10":
		print("\n    [01] dos2unix: convierte entre archivos de texto DOS y Unix")
		print("    [02] exiftool: utilidad para leer, escribir y editar metainformación en una amplia variedad de archivos")
		print("    [03] iconv: Utilidad de conversión entre diferentes codificaciones de caracteres")
		print("    [04] mediainfo: utilidad de línea de comandos para leer información de archivos multimedia")
		print("    [05] pdfinfo: extractor de información de documentos PDF")
		print("\n    [00] salir al menu\n")
		reportls = input("lzmx > set_install ")
		if reportls == "@":
			reportls = ""
			for x in range(1,201):
				reportls += f"{x} "
		if len(reportls.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for reportx in reportls.split():
			if reportx.strip() == "01" or reportx.strip() == "1": dos2unix()
			elif reportx.strip() == "02" or reportx.strip() == "2": exiftool()
			elif reportx.strip() == "03" or reportx.strip() == "3": iconv()
			elif reportx.strip() == "04" or reportx.strip() == "4": mediainfo()
			elif reportx.strip() == "05" or reportx.strip() == "5": pdfinfo()
			elif reportx.strip() == "00" or reportx.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	
	# 11 - Forensic Tools
	elif lazymux.strip() == "11":
		print("\n    [01] steghide: incrusta un mensaje en un archivo reemplazando algunos de los bits menos significativos")
		print("    [02] tesseract: Tesseract es probablemente el motor OCR de código abierto más preciso disponible")
		print("    [03] sleuthkit: The Sleuth Kit (TSK) es una biblioteca de herramientas forenses digitales")
		print("    [04] CyberScan: kit de herramientas forenses de la red")
		print("    [05] binwalk: herramienta de análisis de firmware")
		print("\n    [00] salir al menu\n")
		forensc = input("lzmx > set_install ")
		if forensc == "@":
			forensc = ""
			for x in range(1,201):
				forensc += f"{x} "
		if len(forensc.split()) > 1:
			writeStatus(1) 
		else:
			writeStatus(0)
		for forenx in forensc.split():
			if forenx.strip() == "01" or forenx.strip() == "1": steghide()
			elif forenx.strip() == "02" or forenx.strip() == "2": tesseract()
			elif forenx.strip() == "03" or forenx.strip() == "3": sleuthkit()
			elif forenx.strip() == "04" or forenx.strip() == "4": cyberscan()
			elif forenx.strip() == "05" or forenx.strip() == "5": binwalk()
			elif forenx.strip() == "00" or forenx.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	
	# 12 - Stress Testing
	elif lazymux.strip() == "12":
		print("\n    [01] Torshammer: herramienta DDOS post lento")
		print("    [02] Slowloris: herramienta DoS de bajo ancho de banda")
		print("    [03] Fl00d y Fl00d2: herramienta de inundación UDP")
		print("    [04] GoldenEye: GoldenEye Layer 7 (KeepAlive+NoCache) herramienta de prueba DoS")
		print("    [05] Xerxes: La herramienta DoS más poderosa")
		print("    [06] Planetwork-DDOS")
		print("    [07] Xshell")
		print("    [08] santet-online: Herramienta de Ingeniería Social")
		print("    [09] dost-attack: herramientas de ataque del servidor web")
		print("    [10] DHCPig: script de agotamiento de DHCP escrito en python usando la biblioteca de red scapy")
		print("\n    [00] salir al menu\n")
		stresstest = input("lzmx > set_install ")
		if stresstest == "@":
			stresstest = ""
			for x in range(1,201):
				stresstest += f"{x} "
		if len(stresstest.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for stressx in stresstest.split():
			if stressx.strip() == "01" or stressx.strip() == "1": torshammer()
			elif stressx.strip() == "02" or stressx.strip() == "2": slowloris()
			elif stressx.strip() == "03" or stressx.strip() == "3": fl00d12()
			elif stressx.strip() == "04" or stressx.strip() == "4": goldeneye()
			elif stressx.strip() == "05" or stressx.strip() == "5": xerxes()
			elif stressx.strip() == "06" or stressx.strip() == "6": planetwork_ddos()
			elif stressx.strip() == "07" or stressx.strip() == "7": xshell()
			elif stressx.strip() == "08" or stressx.strip() == "8": sanlen()
			elif stressx.strip() == "09" or stressx.strip() == "9": dostattack()
			elif stressx.strip() == "10": dhcpig()
			elif stressx.strip() == "00" or stressx.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	
	# 13 - Install Linux Distro
	elif lazymux.strip() == "13":
		print("\n    [01] Ubuntu")
		print("    [02] Fedora")
		print("    [03] Kali Nethunter")
		print("    [04] Parrot")
		print("    [05] Arch Linux")
		print("\n    [00] salir al menu\n")
		innudis = input("lzmx > set_install ")
		if innudis == "@":
			innudis = ""
			for x in range(1,201):
				innudis += f"{x} "
		if len(innudis.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for innux in innudis.split():
			if innux.strip() == "01" or innux.strip() == "1": ubuntu()
			elif innux.strip() == "02" or innux.strip() == "2": fedora()
			elif innux.strip() == "03" or innux.strip() == "3": nethunter()
			elif innux.strip() == "04" or innux.strip() == "4": parrot()
			elif innux.strip() == "05" or innux.strip() == "5": archlinux()
			elif innux.strip() == "00" or innux.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	
	# 14 - Termux Utility
	elif lazymux.strip() == "14":
		print("\n    [01] SpiderBot: sitio web de Curl usando proxy aleatorio y agente de usuario")
		print("    [02] Ngrok: canalice los puertos locales a las URL públicas e inspeccione el tráfico")
		print("    [03] Sudo: instalador de sudo para Android")
		print("    [04] google: enlaces de Python al motor de búsqueda de Google")
		print("    [05] kojawafft")
		print("    [06] ccgen: generador de tarjetas de crédito")
		print("    [07] VCRT: creador de Virus")
		print("    [08] Código electrónico: Codificador de secuencias de comandos PHP")
		print("    [09] Termux-Styling")
		print("    [11] xl-py: Paquete de Compra Directa XL")
		print("    [12] BeanShell: un pequeño intérprete de fuente de Java gratuito e integrable con funciones de lenguaje de secuencias de comandos de objetos, escrito en Java")
		print("    [13] vbug: creador de virus")
		print("    [14] Crunch: generador de listas de palabras altamente personalizable")
		print("    [15] Texte: herramienta sencilla para ejecutar texto")
		print("    [16] heroku: CLI para interactuar con Heroku")
		print("    [17] RShell: caparazón inverso para escuchar solo")
		print("    [18] TermPyter: solucione todos los errores de instalación de Jupyter en termux")
		print("    [19] Numpy: El paquete fundamental para la computación científica con Python")
		print("    [20] Comprobador de BTC a IDR: verifique el tipo de cambio de la moneda de dinero virtual a la rupia indonesia desde la API de Bitcoin.co.id")
		print("    [21] ClickBot: gana dinero con el bot de Telegram")
		print("\n    [00] salir al menu\n")
		moretool = input("lzmx > set_install ")
		if moretool == "@":
			moretool = ""
			for x in range(1,201):
				moretool += f"{x} "
		if len(moretool.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for moret in moretool.split():
			if moret.strip() == "01" or moret.strip() == "1": spiderbot()
			elif moret.strip() == "02" or moret.strip() == "2": ngrok()
			elif moret.strip() == "03" or moret.strip() == "3": sudo()
			elif moret.strip() == "04" or moret.strip() == "4": google()
			elif moret.strip() == "05" or moret.strip() == "5": kojawafft()
			elif moret.strip() == "06" or moret.strip() == "6": ccgen()
			elif moret.strip() == "07" or moret.strip() == "7": vcrt()
			elif moret.strip() == "08" or moret.strip() == "8": ecode()
			elif moret.strip() == "09" or moret.strip() == "9": stylemux()
			elif moret.strip() == "10": passgencvar()
			elif moret.strip() == "11": xlPy()
			elif moret.strip() == "12": beanshell()
			elif moret.strip() == "13": vbug()
			elif moret.strip() == "14": crunch()
			elif moret.strip() == "15": textr()
			elif moret.strip() == "16": heroku()
			elif moret.strip() == "17": rshell()
			elif moret.strip() == "18": termpyter()
			elif moret.strip() == "19": numpy()
			elif moret.strip() == "20": btc2idr()
			elif moret.strip() == "21": clickbot()
			elif moret.strip() == "00" or moret.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	
	# 15 - Shell Function [.bashrc]
	elif lazymux.strip() == "15":
		print("\n  [01] FBVid (Descargador de videos de FB)")
		print("    [02] cast2video (Convertidor Asciinema Cast)")
		print("    [03] cionset (Icono de la aplicación AIDE)")
		print("    [04] readme (GitHub README.md)")
		print("    [05] makedeb (Generador de paquetes DEB)")
		print("    [06] quikfind (Buscar archivos)")
		print("    [07] pranayama (4-7-8 Respiración Relajada)")
		print("    [08] sqlc (procesador de consultas SQLite)")
		print("\n    [00] salir al menu\n")
		myshf = input("lzmx > set_install ")
		if myshf == "@":
			myshf = ""
			for x in range(1,201):
				myshf += f"{x} "
		if len(myshf.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for mysh in myshf.split():
			if mysh.strip() == "01" or mysh.strip() == "1": fbvid()
			elif mysh.strip() == "02" or mysh.strip() == "2": cast2video()
			elif mysh.strip() == "03" or mysh.strip() == "3": iconset()
			elif mysh.strip() == "04" or mysh.strip() == "4": readme()
			elif mysh.strip() == "05" or mysh.strip() == "5": makedeb()
			elif mysh.strip() == "06" or mysh.strip() == "6": quikfind()
			elif mysh.strip() == "07" or mysh.strip() == "7": pranayama()
			elif mysh.strip() == "08" or mysh.strip() == "8": sqlc()
			elif mysh.strip() == "00" or mysh.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	
	# 16 - Install CLI Games
	elif lazymux.strip() == "16":
		print("\n    [01] pájaro volador")
		print("    [02] Tranvía")
		print("    [03] Escritura rápida")
		print("    [04] NSnake: El clásico juego de serpientes con interfaz textual")
		print("    [05] Moon buggy: juego simple en el que conduces un automóvil por la superficie de la luna")
		print("    [06] Nudoku: juego de sudoku basado en ncurses")
		print("    [07] tty-solitario")
		print("    [08] Pacman4Console")
		print("\n    [00] salir al menu\n")
		cligam = input("lzmx > set_install ")
		if cligam == "@":
			cligam = ""
			for x in range(1,201):
				cligam += f"{x} "
		if len(cligam.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for clig in cligam.split():
			if clig.strip() == "01" or clig.strip() == "1": flappy_bird()
			elif clig.strip() == "02" or clig.strip() == "2": street_car()
			elif clig.strip() == "03" or clig.strip() == "3": speed_typing()
			elif clig.strip() == "04" or clig.strip() == "4": nsnake()
			elif clig.strip() == "05" or clig.strip() == "5": moon_buggy()
			elif clig.strip() == "06" or clig.strip() == "6": nudoku()
			elif clig.strip() == "07" or clig.strip() == "7": ttysolitaire()
			elif clig.strip() == "08" or clig.strip() == "8": pacman4console()
			elif clig.strip() == "00" or clig.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	
	# 17 - Malware Analysis
	elif lazymux.strip() == "17":
		print("\n    [01] Lynis: auditoría de seguridad y análisis de rootkits")
		print("    [02] Chkrootkit: un analizador de rootkits de Linux")
		print("    [03] ClamAV: kit de herramientas de software antivirus")
		print("    [04] Yara: herramienta destinada a ayudar a los investigadores de malware a identificar y clasificar muestras de malware")
		print("    [05] VirusTotal-CLI: interfaz de línea de comandos para VirusTotal")
		print("    [06] avpass: herramienta para filtrar y eludir el sistema de detección de malware de Android")
		print("    [07] DKMC: no mates a mi gato - Herramienta maliciosa de evasión de carga útil")
		print("\n    [00] salir al menu\n")
		malsys = input("lzmx > set_install ")
		if malsys == "@":
			malsys = ""
			for x in range(1,201):
				malsys += f"{x} "
		if len(malsys.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for malx in malsys.split():
			if malx.strip() == "01" or malx.strip() == "1": lynis()
			elif malx.strip() == "02" or malx.strip() == "2": chkrootkit()
			elif malx.strip() == "03" or malx.strip() == "3": clamav()
			elif malx.strip() == "04" or malx.strip() == "4": yara()
			elif malx.strip() == "05" or malx.strip() == "5": virustotal()
			elif malx.strip() == "06" or malx.strip() == "6": avpass()
			elif malx.strip() == "07" or malx.strip() == "7": dkmc()
			elif malx.strip() == "00" or malx.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	
	# 18 - Compiler/Interpreter
	elif lazymux.strip() == "18":
		print("\n    [01] Python2: lenguaje de programación Python 2 destinado a habilitar programas claros")
		print("    [02] ecj: compilador de Eclipse para Java")
		print("    [03] Golang: Go programming language compiler")
		print("    [04] ldc: compilador del lenguaje de programación D, creado con LLVM")
		print("    [05] Nim: compilador del lenguaje de programación Nim")
		print("    [06] shc: Shell script compiler")
		print("    [07] TCC: Compilador Tiny C")
		print("    [08] PHP: lenguaje de secuencias de comandos integrado en HTML del lado del servidor")
		print("    [09] Ruby: lenguaje de programación dinámico con un enfoque en la simplicidad y la productividad")
		print("    [10] Perl: lenguaje de programación capaz y rico en funciones")
		print("    [11] Vlang: Lenguaje simple, rápido, seguro y compilado para desarrollar software mantenible")
		print("    [12] BeanShell: Intérprete de Java pequeño, gratuito, integrable, a nivel de fuente con funciones de lenguaje de secuencias de comandos basadas en objetos escritas en Java")
		print("    [13] fp-compiler: Free Pascal es un compilador Pascal profesional de 32, 64 y 16 bits")
		print("    [14] Octave: lenguaje de programación científica")
		print("    [15] BlogC: un compilador de blogs")
		print("    [16] Dart: lenguaje de programación de propósito general")
		print("    [17] Yasm: Ensamblador compatible con los conjuntos de instrucciones x86 y AMD64")
		print("    [18] Nasm: un ensamblador x86 multiplataforma con una sintaxis similar a la de Intel")
		print("\n    [00] salir al menu\n")
		compter = input("lzmx > set_install ")
		if compter == "@":
			compter = ""
			for x in range(1,201):
				compter += f"{x} "
		if len(compter.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for compt in compter.split():
			if compt.strip() == "01" or compt.strip() == "1": python2()
			elif compt.strip() == "02" or compt.strip() == "2": ecj()
			elif compt.strip() == "03" or compt.strip() == "3": golang()
			elif compt.strip() == "04" or compt.strip() == "4": ldc()
			elif compt.strip() == "05" or compt.strip() == "5": nim()
			elif compt.strip() == "06" or compt.strip() == "6": shc()
			elif compt.strip() == "07" or compt.strip() == "7": tcc()
			elif compt.strip() == "08" or compt.strip() == "8": php()
			elif compt.strip() == "09" or compt.strip() == "9": ruby()
			elif compt.strip() == "10": perl()
			elif compt.strip() == "11": vlang()
			elif compt.strip() == "12": beanshell()
			elif compt.strip() == "13": fpcompiler()
			elif compt.strip() == "14": octave()
			elif compt.strip() == "15": blogc()
			elif compt.strip() == "16": dart()
			elif compt.strip() == "17": yasm()
			elif compt.strip() == "18": nasm()
			elif compt.strip() == "00" or compt.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	
	# 19 - Social Engineering Tools
	elif lazymux.strip() == "19":
		print("\n    [01] weeman: servidor HTTP para phishing en python")
		print("    [02] SocialFish: herramienta educativa de phishing y recopilador de información")
		print("    [03] santet-online: Herramienta de Ingeniería Social")
		print("    [04] SpazSMS: envíe mensajes no solicitados repetidamente en el mismo número de teléfono")
		print("    [05] LiteOTP: SMS OTP multispam")
		print("    [06] F4K3: Generador de datos de usuarios falsos")
		print("    [07] Hac")
		print("    [08] Cokie-stealter: Robador de cokies de mierda (eso dice en traductor)")
		print("    [09] zphisher: herramienta de phishing automatizada")
		print("\n    [00] salir al menu\n")
		soceng = input("lzmx > set_install ")
		if soceng == "@":
			soceng = ""
			for x in range(1,201):
				soceng += f"{x} "
		if len(soceng.split()) > 1:
			writeStatus(1)
		else:
			writeStatus(0)
		for socng in soceng.split():
			if socng.strip() == "01" or socng.strip() == "1": weeman()
			elif socng.strip() == "02" or socng.strip() == "2": socfish()
			elif socng.strip() == "03" or socng.strip() == "3": sanlen()
			elif socng.strip() == "04" or socng.strip() == "4": spazsms()
			elif socng.strip() == "05" or socng.strip() == "5": liteotp()
			elif socng.strip() == "06" or socng.strip() == "6": f4k3()
			elif socng.strip() == "07" or socng.strip() == "7": hac()
			elif socng.strip() == "08" or socng.strip() == "8": cookiestealer()
			elif socng.strip() == "09" or socng.strip() == "9": zphisher()
			elif socng.strip() == "00" or socng.strip() == "0": restart_program()
			else: print("\nERROR: Wrong Input");timeout(1);restart_program()
		if readStatus():
			writeStatus(0)
	elif lazymux.strip() == "00":
		sys.exit()
	
	else:
		print("\nERROR: opcion no encontrada")
		timeout(1)
		restart_program()

if __name__ == "__main__":
	os.system("clear")
	main()
