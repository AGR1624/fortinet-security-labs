\# Lab 01: Inspección Profunda SSL/TLS (Deep Packet Inspection - DPI) con PKI Propia



\## Ficha Técnica y Cumplimiento



| Campo | Detalle |

| :--- | :--- |

| \*\*ID del Documento\*\* | SOP-SEC-001 |

| \*\*Versión / Fecha\*\* | v1.1 — Noviembre 2026 |

| \*\*Plataforma\*\* | VMware Workstation Pro, FortiGate-VM64 (FortiOS 7.6.8 Trial), Kali Linux 2026.3 |

| \*\*Controles ISO/IEC 27002:2022\*\* | \*\*A.8.24\*\* (Uso de criptografía), \*\*A.8.23\*\* (Filtrado web), \*\*A.8.15\*\* (Registro de eventos), \*\*A.8.20\*\* (Seguridad de redes) |

| \*\*Marco NIST\*\* | NIST SP 800-41 Rev. 1 / NIST CSF 2.0 (\*Protect\* y \*Detect\*) |



\---



\## 1. Escenario y Objetivo de Negocio



Con la inspección básica por certificado (`certificate-inspection`), el firewall únicamente inspecciona el encabezado SNI del saludo TLS (por ejemplo, `wikipedia.org` o `github.com`), siendo incapaz de auditar rutas internas, parámetros de búsqueda o descargas de archivos dentro de sesiones HTTPS.



El objetivo de este laboratorio es implementar \*\*Inspección Profunda SSL/TLS (DPI)\*\* mediante una Autoridad Certificadora (CA) interna de 2048 bits para descifrar tráfico HTTPS de forma transparente, auditar URLs completas y aplicar controles granulares por ruta específica, extensión de archivo y palabras clave sin depender de licencias en la nube de FortiGuard.



\---



\## 2. Topología y Direccionamiento



```mermaid

flowchart LR

&#x20;   K\[Kali Linux 2026.3<br/>192.168.10.2/24<br/>Almacén OS + Firefox NSS] -- "HTTPS cifrado con CA FortiDPI\_2048" --> FG\[FortiGate VM64<br/>port2: 192.168.10.1<br/>port1: NAT VMnet8]

&#x20;   FG -- "HTTPS cifrado con Cert Público" --> W((Internet<br/>Wikipedia / GitHub / W3C))

```



| Dispositivo | Interfaz | Red Virtual | Dirección IP | Rol |

| :--- | :--- | :--- | :--- | :--- |

| \*\*FortiGate-VM64\*\* | `port1` | VMnet8 (NAT) | DHCP (`192.168.167.x`) | WAN / Salida a Internet |

| \*\*FortiGate-VM64\*\* | `port2` | VMnet2 (Host-only) | `192.168.10.1/24` | LAN / Gateway + Proxy DPI |

| \*\*Kali Linux 2026.3\*\* | `eth0` | VMnet2 (Host-only) | `192.168.10.2/24` | Cliente interno auditado |



\---



\## 3. Implementación Técnica



\### 3.1 Generación de CA Propia (RSA 2048 bits) en Kali Linux

Debido a que la CA integrada por defecto (`Fortinet\_CA\_SSL`) utiliza RSA de 1024 bits y es rechazada por navegadores modernos, se generó una entidad certificadora conforme a estándares criptográficos vigentes (`CN = FortiGate\_DPI\_2048`):



```bash

openssl req -x509 -newkey rsa:2048 -nodes \\

&#x20; -keyout FortiDPI\_2048.key \\

&#x20; -out FortiDPI\_2048.crt \\

&#x20; -days 3650 \\

&#x20; -subj "/CN=FortiGate\_DPI\_2048" \\

&#x20; -addext "basicConstraints=critical,CA:TRUE" \\

&#x20; -addext "keyUsage=critical,keyCertSign,cRLSign"

```



\### 3.2 Distribución de Confianza en el Cliente (OS y Firefox)

1\. \*\*Almacén raíz del sistema operativo (`curl`, `wget`, `openssl`, `apt`):\*\*

&#x20;  ```bash

&#x20;  sudo cp FortiDPI\_2048.crt /usr/local/share/ca-certificates/FortiDPI\_2048.crt

&#x20;  sudo update-ca-certificates

&#x20;  ```

2\. \*\*Almacén NSS de Firefox:\*\* Importación manual desde `about:preferences#privacy` > \*Certificates\* > \*View Certificates\* > \*Authorities\* marcando \*"Trust this CA to identify websites"\*.



\### 3.3 Conversión e Importación de la CA en FortiOS 7.6.8

OpenSSL 3.x genera claves privadas en formato PKCS#8 (`-----BEGIN PRIVATE KEY-----`), mientras que FortiOS exige formato RSA tradicional PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`):



```bash

openssl rsa -in FortiDPI\_2048.key -traditional -out FortiDPI\_2048\_rsa.key

```



La clave convertida y el certificado público se cargaron en `config vpn certificate local` bajo el objeto `"FortiDPI\_2048"` (`CN = FortiGate\_DPI\_2048`).



\### 3.4 Políticas de Filtrado Granular e Inspección

\* \*\*SSL/SSH Inspection (`custom-deep-inspection`):\*\* Se asignó `FortiDPI\_2048` como \*CA certificate\*.

\* \*\*Web Filter (`Laboratorio`):\*\* Se configuró \*Rating Options\* en \*Allow all websites\* y se implementaron 4 reglas en \*Static URL Filter\*:

&#x20; 1. `es.wikipedia.org/wiki/Linux` (\*Simple\* / \*Block\*) — Bloqueo de artículo específico dentro de Wikipedia.

&#x20; 2. `github.com/torvalds/linux` (\*Simple\* / \*Block\*) — Bloqueo de repositorio específico dentro de GitHub.

&#x20; 3. `\*.pdf` (\*Wildcard\* / \*Block\*) — Prevención de descarga de documentos PDF dentro de sesiones HTTPS.

&#x20; 4. `\*kali\*` (\*Wildcard\* / \*Block\*) — Bloqueo por palabra clave en cualquier ruta URL.

\* \*\*Firewall Policy (`Laboratorio`):\*\* Restringida a los servicios `DNS`, `HTTP` y `HTTPS` con NAT activo, vinculando los perfiles `Laboratorio` (Web Filter) y `custom-deep-inspection` (SSL Inspection) con registro en `All Sessions`.



\---



\## 4. Validación y Evidencias



\### 4.1 Subrutas en Wikipedia (`Allowed` vs. `Blocked`)

Al acceder a `https://es.wikipedia.org/wiki/Fortinet` el sitio carga con normalidad bajo el certificado `FortiGate\_DPI\_2048`, mientras que `https://es.wikipedia.org/wiki/Linux` dentro del mismo dominio es interceptado y bloqueado.



!\[Acceso permitido a ruta Fortinet](evidence/01-allowed-https-fortinet.png)

!\[Bloqueo granular en ruta Linux](evidence/02-blocked-https-linux.png)



\### 4.2 Repositorios Específicos en GitHub (`Allowed` vs. `Blocked`)

Bajo el mismo encabezado SNI (`github.com`), FortiGate descifra la petición HTTP interna para permitir `https://github.com/fortinet` y bloquear `https://github.com/torvalds/linux`.



!\[Acceso permitido a GitHub Fortinet](evidence/03-allowed-github-fortinet.png)

!\[Bloqueo granular en repositorio GitHub](evidence/04-blocked-github-torvalds.png)



\### 4.3 Bloqueo de Descarga `.pdf` y Filtrado por Palabra Clave (`\*kali\*`) en HTTPS

El motor DPI inspecciona las rutas y extensiones solicitadas dentro del túnel cifrado, bloqueando tanto la descarga directa de archivos `.pdf` como cualquier ruta que contenga palabras restringidas.



!\[Bloqueo de extensión PDF en HTTPS](evidence/05-blocked-https-pdf-extension.png)

!\[Bloqueo por palabra clave en URL](evidence/06-blocked-keyword-kali.png)



\### 4.4 Validación Criptográfica por Consola (`openssl` y `curl`)

Verificación mediante `openssl s\_client` confirmando que el emisor es la CA propia (`issuer=CN = FortiGate\_DPI\_2048`) y contraste con `curl`.



!\[Validación CLI con OpenSSL y Curl](evidence/07-cli-openssl-curl-validation.png)



\### 4.5 Pruebas Adicionales de Contraste URL (`Allowed` vs. `Blocked`)

Validación complementaria de navegación limpia frente a intercepción activa del filtro local.



!\[Prueba adicional URL permitida](evidence/08-allowed-url.png)

!\[Prueba adicional URL bloqueada](evidence/09-blocked-url.png)



\### 4.6 Auditoría de Eventos en FortiGate (`Web Filter Logs`)

En \*\*Log \& Report > Security Events > Web Filter\*\*, el firewall registra cada bloqueo mostrando la URL completa descifrada originada desde `192.168.10.2`.



!\[Auditoría de URL completa en FortiGate](evidence/10-logs-web-filter.png)



\---



\## 5. Matriz de Troubleshooting (Incidencias Resueltas)



| Síntoma / Error | Causa Raíz | Solución Aplicada |

| :--- | :--- | :--- |

| Botón \*Clone\* deshabilitado en el perfil `deep-inspection` | Los perfiles predeterminados del sistema son de solo lectura en la GUI de FortiOS 7.6.8. | Se utilizó y personalizó el perfil editable integrado `custom-deep-inspection`. |

| El botón de menú \*Settings\* en Firefox no abría la ventana en Kali | Fallo de renderizado de menús emergentes en el entorno gráfico XFCE. | Se accedió directamente mediante la URL interna `about:preferences#privacy` en la barra de direcciones. |

| `MOZILLA\_PKIX\_ERROR\_INADEQUATE\_KEY\_SIZE` al navegar | La CA predeterminada `Fortinet\_CA\_SSL` usa RSA de 1024 bits; Firefox exige mínimo 2048 bits. | Se generó e instaló una CA propia de 2048 bits (`FortiDPI\_2048` / `CN = FortiGate\_DPI\_2048`) con extensiones `CA:TRUE` y `keyCertSign`. |

| `Incorrect certificate file key size for CA/LOCAL/REMOTE cert.` | OpenSSL 3.x genera claves PKCS#8 y archivos `.p12` con cifrado PBES2/AES no soportados por el importador web de FortiOS 7.6.8. | Se convirtió la clave privada a RSA tradicional (`-traditional`) y se cargó directamente por CLI/SSH. |

| `Invalid private key` / truncamiento al pegar en Web CLI | La consola web de FortiOS limita el pegado a \~1,000 caracteres y corta líneas Base64. | Se envió el bloque completo de clave y certificado mediante tubería (`pipe`) SSH / bloques segmentados hacia `192.168.10.1`. |

