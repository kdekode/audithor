# Audithor

Creado por **steev anderson**. Herramienta de consola para un servidor Linux/Plesk activo. No utiliza idxo-security ni su instalador.

## Preparación

Sube `audithor.py` y el lanzador `audithor` a **`/too-custom/audithor/`**, fuera de cualquier raíz web. Requiere Python **3.9+** y las zonas horarias del sistema. No usa pip ni paquetes externos de Python. Comprueba la versión existente con `/usr/bin/python3 --version`; el programa no instala nada si falta un requisito.

La carpeta y ambos archivos deben pertenecer a una cuenta administradora y no permitir escritura a usuarios de las webs, especialmente si vas a ejecutarlo como root. No ejecutes como root una copia modificable mediante FTP de una web. Puedes omitir el lanzador y ejecutar directamente Python:

```sh
/usr/bin/python3 -I -B /too-custom/audithor/audithor.py
```

`-I` aísla Python del directorio actual y de variables de entorno de importación; `-B` evita crear archivos de bytecode. Si usas el lanzador, ejecútalo mediante `sh /too-custom/audithor/audithor`; ya incluye esas opciones. No hay que ejecutar un instalador.

Para dar prioridad de disco mínima, si `ionice` ya está instalado:

```sh
ionice -c 3 /usr/bin/python3 -I -B /too-custom/audithor/audithor.py
```

No modifica prioridades del servidor: cambia únicamente la prioridad del propio proceso. Sin `ionice`, sigue funcionando, pero no aplica prioridad de disco idle. Utiliza una cuenta con permisos de lectura ya existentes; no cambia permisos para conseguir acceso. Root permite leer los logs, pero no es necesario si la cuenta ya tiene acceso.

Si se aplaza por carga, consulta el diagnóstico sin analizar logs:

```sh
/usr/bin/python3 -I -B /too-custom/audithor/audithor.py --diagnose
```

Muestra carga media de 1/5/15 minutos, CPU lógicas, umbral aplicado y memoria disponible. La carga media no es el porcentaje de CPU: también puede reflejar procesos en espera de disco. El umbral es conservador; un rechazo no demuestra por sí solo que la CPU esté saturada. No desactives las guardas sin revisar el estado real del servidor.

El umbral de carga es de 1 por CPU lógica en ambos modos (8 en un host de 8 CPU). `--gentle` permite una lectura más lenta: aplica 10 ms de pausa por línea/fragmento, aproximadamente un máximo de 100 líneas/s. Por encima del umbral aplaza la lectura; conserva el mínimo de memoria disponible de 256 MiB y los presupuestos. No garantiza que el servidor tenga capacidad libre: la carga media es una señal aproximada, no una medición de CPU o latencia de disco. Prueba primero solo un dominio:

```sh
/usr/bin/python3 -I -B /too-custom/audithor/audithor.py ejemplo.com --gentle --sample --seconds 2 --max-mib 1 --no-fail2ban
```

El diagnóstico también acepta `--gentle`. Sin esta opción se aplica una pausa de 1 ms y el mismo umbral de 1 por CPU lógica. En lectura continua las guardas se comprueban cada 100 fragmentos: aproximadamente cada segundo en modo lento, más el tiempo de lectura. Si la carga o memoria no permiten seguir, espera y recomprueba cada 5 segundos, avisando cada 30 segundos. No aumenta el umbral para forzar la lectura. La espera puede ser indefinida si el servidor no se recupera; Ctrl+C termina el proceso.

## Uso

Hoy, informes progresivos por dominio y resumen final de cinco filas por página:

```sh
/usr/bin/python3 -I -B /too-custom/audithor/audithor.py
```

Lee los dominios secuencialmente y **muestra el informe de cada uno en cuanto acaba**. Tras cinco dominios, espera a que escribas exactamente **`start`** y Enter para analizar los siguientes cinco; Enter solo no inicia otra tanda. `q` termina y muestra el resumen de lo analizado. Conserva únicamente un resumen pequeño por dominio. Al terminar presenta una lista compacta **por prioridad de revisión**: primero los dominios con más umbrales activados (0–3); en empate, más accesos sensibles con respuesta 4xx, más respuestas 5xx, más 4xx, más peticiones y nombre. Son criterios orientativos, no una medida de ataques o daños. Los dominios sin accesos de la fecha aparecen al final sin valoración.

En el resumen final, Enter muestra las siguientes cinco filas sin releer logs; `q` termina. Ctrl+C durante el recorrido muestra el resumen parcial de los dominios ya terminados; otra interrupción termina. Sin terminal interactiva, el modo normal analiza solo los primeros cinco dominios. `--once` también limita el análisis a la primera tanda. Los modos `--report` y `--send` recorren automáticamente todos los dominios, sin esperar `start`, y muestran las primeras cinco filas del resumen final para no bloquearse. Los dominios sin datos no se interpretan como tráfico cero. Si sube la carga, el modo continuo espera y retoma; `--sample` mantiene la interrupción por presupuesto/carga.

El inventario se recorre inicialmente por modificación de logs; ese es el orden de los informes progresivos y no determina el orden del resumen final. La espera hasta el primer informe depende solo del primer dominio y de las pausas. El recorrido entero puede durar horas en una instalación grande, pero se ven resultados mientras avanza. En la vista normal no se mantienen tablas de URLs ni se consulta Fail2Ban. Al exportar se calculan los detalles de un dominio, se escriben en HTML y se descartan antes de pasar al siguiente. No realiza una segunda lectura para preparar el resumen.

Ayer / fecha histórica / dominio concreto:

```sh
/usr/bin/python3 -I -B /too-custom/audithor/audithor.py --yesterday
/usr/bin/python3 -I -B /too-custom/audithor/audithor.py --date 2026-10-18 --gzip
/usr/bin/python3 -I -B /too-custom/audithor/audithor.py ejemplo.com
/usr/bin/python3 -I -B /too-custom/audithor/audithor.py ejemplo.com --yesterday --gzip
```

Para obtener un informe completo de un dominio con lectura lenta y memoria acotada:

```sh
ionice -c 3 /usr/bin/python3 -I -B /too-custom/audithor/audithor.py ejemplo.com --gentle --gzip
```

**Modo continuo predeterminado:** `--seconds` (1–1800) y `--max-mib` (1–1024) delimitan una tanda, no el total del dominio. Tras cada tanda descansa un segundo y continúa desde el mismo archivo/posición, conservando acumulados. Por defecto las tandas son de 30 segundos o unos 64 MiB descomprimidos; puede sobrepasar ligeramente el límite de bytes para terminar una línea. No carga el archivo entero en RAM. Mantiene el archivo/gzip abierto mientras descansa, sin volver a descomprimir el principio. Los archivos activos de texto se leen hasta el tamaño capturado al abrirlos; no persigue su crecimiento indefinidamente. Los gzip rotados se presuponen estáticos. Recorre todos los archivos seleccionados, incluso otras fechas, para filtrar cada línea con rigor; esto puede tardar mucho con una retención larga.

**Modo `--sample`:** conserva el comportamiento anterior, limitado a una tanda por dominio y con avisos PARCIAL al agotarla. Para una prueba de dos segundos en total, indica un dominio concreto, `--sample --seconds 2 --max-mib 1 --no-fail2ban`. Sin `--sample`, poner `--seconds 2` solo hace las tandas más cortas y no acota el tiempo total.

Ambos modos mantienen las pausas de 1 ms (10 ms con `--gentle`) por línea/fragmento. El estado solo vive durante esta ejecución: cerrar SSH, terminar el proceso o volver a ejecutar empieza de nuevo. No hay cachés ni reanudación entre procesos. `--once` limita el análisis a los primeros cinco dominios. Acabar la lectura no demuestra que Plesk haya conservado todo el tráfico del día.

## Auditoría HTML y envío de correo

Crear un informe de todos los dominios de ayer, sin correo:

```sh
python3 -I -B audithor.py --yesterday --report
```

Crear el mismo informe y solicitar envío a **notificacion@indexeomarketing.com**:

```sh
python3 -I -B audithor.py --yesterday --send
```

Para auditar y enviar solo una web:

```sh
python3 -I -B audithor.py ejemplo.com --yesterday --send
```

Estos modos activan automáticamente `--gentle` y recorren los dominios uno a uno, sin pausas de teclado. Mantienen las esperas por carga y el límite de memoria virtual de 128 MiB. El trabajo principal sigue siendo leer los logs: generar HTML no requiere navegador, motor de PDF, paquetes ni fuentes externas. HTML no garantiza un tamaño menor que cualquier PDF, pero evita esas dependencias y el coste de renderizado. Es una auditoría del tráfico y errores de logs disponibles; no un escaneo activo de vulnerabilidades.

Guarda **un único HTML por ejecución**, con un apartado por dominio y resumen final, en `reports/audithor-FECHA-ID.html` junto al script. Incluye métricas, clasificación, picos, códigos HTTP, veinte principales URLs/IP/rutas sensibles/errores, categorías de mensajes internos y coincidencias Fail2Ban cuando estén disponibles. Los rankings conservan los límites de cardinalidad ya documentados. Fail2Ban se lee una sola vez al exportar para compartir el conjunto de IP entre dominios; su presupuesto puede dejarlo parcial. Se escribe cada dominio conforme acaba, sin acumular todos los detalles en RAM. El informe completo puede requerir horas si hay muchos logs.

El directorio `reports/` se crea solo al exportar, con permisos 700; cada HTML usa nombre aleatorio exclusivo y permisos 600. Rechaza enlaces y carpetas existentes que no sean privadas o del usuario actual; no cambia sus permisos automáticamente. Mantén la aplicación y `reports/` fuera de la raíz web. **Añade `reports/` a tu `.gitignore` existente**: los informes contienen IP y rutas privadas. No se borran automáticamente; elimina los informes antiguos que ya no necesites para controlar el espacio.

Límite de HTML: **2 MiB** por ejecución. Si lo alcanza, se marca parcial y se conserva el archivo sin enviarlo. Un recorrido interrumpido también conserva un HTML parcial y no solicita envío. `--send --once` en un inventario de más de cinco dominios deja un informe parcial sin enviar; para probar el correo con poco trabajo, indica un único dominio. `--sample --send` permite un informe de muestra explícitamente marcado como tal si se visitan todos los dominios seleccionados; no lo presenta como tráfico completo.

El envío usa exclusivamente **`/usr/sbin/sendmail -oi -t`**, si ya existe y está configurado. No instala un MTA, configura SMTP, modifica Plesk ni reinicia servicios. El remitente y destinatario son `notificacion@indexeomarketing.com`. Se envía **un solo correo con un adjunto HTML**, no un correo por dominio. La construcción MIME solo carga un archivo acotado de hasta 2 MiB; el proceso de envío tiene timeout de 20 segundos, hereda prioridad/límites del script y no usa shell. No reintenta automáticamente.

Si falta el servicio o falla, el HTML permanece guardado y se indica el problema. Aceptación por el MTA no confirma entrega al buzón: filtros, configuración del servidor y políticas del dominio pueden impedirla. Para comprobar la disponibilidad sin enviar nada: `ls -l /usr/sbin/sendmail`. El script no solicita ni guarda contraseñas de correo. Fuentes: [interfaz sendmail de Postfix](https://manpages.debian.org/trixie/postfix/sendmail.1.en.html), [biblioteca email de Python](https://docs.python.org/3/library/email.message.html).

## Qué significa cada dato

| Dato | Fuente y límites |
|---|---|
| Tráfico | Número de peticiones y bytes de respuesta registrados. No son visitas ni usuarios únicos. |
| Bots/automatización probable | Clasificación heurística del User-Agent, que se puede falsificar. |
| Humano probable | Agentes de navegadores habituales sin indicadores básicos de acceso sensible. No acredita humanidad. |
| Desconocido | Resto; las tres clases suman aproximadamente 100%, salvo redondeo. |
| IP coincidentes F2B | Número de IP vistas en accesos de esa web y con un evento `Ban` de Fail2Ban ese mismo día. No atribuye el motivo del bloqueo al dominio, ni indica si siguen bloqueadas. `N/D` si no hay datos de lectura de alguno de los dos historiales. |
| RAM y CPU por dominio | Se han retirado del informe. No están en los access logs; no se reconstruyen para ayer ni para un total histórico sin registros previos de procesos/pools/cgroups. Ni los bytes ni las peticiones son una medida de CPU. |
| URLs con más consumo | Se muestra transferencia en bytes y número de peticiones, sin atribuirles CPU/RAM. |
| Errores | HTTP 4xx/5xx por ruta, más categorías de mensajes internos de nginx/Apache/PHP cuando hay presupuesto y formato reconocible. Nunca se imprimen mensajes internos completos. |

El informe usa una sola pareja de columnas, «QUÉ SE HA MEDIDO / RESULTADO». «58 (2,1% de las leídas)» en respuestas 4xx significa 58 de **todas las peticiones leídas de esa fecha**, no 58 personas ni un dato asociado a la métrica anterior. 403 indica acceso rechazado; 404, recurso no encontrado. La fila 5xx muestra errores del servidor (por ejemplo 500/503), incluyendo cero si no se observaron. «Contenido enviado» suma el tamaño de respuesta registrado por el formato del log, normalmente cuerpo de respuesta, sin estimar consumo de RAM/CPU ni representar la velocidad de la conexión.

El pico es el mayor recuento observado en un minuto natural, con su fecha/hora/offset cuando hay datos. No es una tasa sostenida ni visitantes: cada imagen, CSS, API y bot puede generar peticiones. Se etiqueta el volumen de ese pico como BAJA (<60/min), MODERADA (60–599/min), ALTA (600–2999/min) o MUY ALTA (>=3000/min). Son rangos orientativos fijos; no se han calibrado a la capacidad ni al historial de cada web. Por ejemplo 355/min son aproximadamente 5,9 solicitudes/s de media dentro de ese minuto, y no activan por sí solas una alerta de ataque.

El nombre ASCII del dominio debe coincidir con su carpeta en `/var/www/vhosts/system`. `--root` permite otra raíz con la misma estructura `dominio/logs`. No usa la API ni la base de datos de Plesk y no hace consultas de red.

Zona por defecto `Europe/Madrid`, modificable con `--timezone`. Los access logs con offset se convierten a esa zona antes de filtrar. Los mensajes internos de nginx/Apache se filtran por su fecha local escrita: al carecer de offset, se presupone que corresponde a la zona elegida. Revisa esta correspondencia si el servidor usa UTC. Solo se interpreta formato combined para accesos y formatos de fecha habituales de nginx/Apache para errores. Líneas no reconocidas generan un aviso en accesos; en logs internos no se contabilizan.

## Históricos y cobertura

Se informa de peticiones **observadas**, fechas encontradas y límites alcanzados. Si no aparecen registros para la fecha, no puede distinguir automáticamente entre ausencia de tráfico, datos eliminados, permisos insuficientes o lectura incompleta. No declara que un día esté completo solo porque haya terminado de leer archivos.

Para hoy, los `.gz` requieren `--gzip`. Para `--yesterday` o una fecha anterior, se incluyen automáticamente. Selecciona una sola capa de accesos: para hoy prefiere nginx `proxy_access_log` / `proxy_access_ssl_log`; para fechas pasadas compara la presencia de históricos numerados y `.processed` de ambas capas. Si Apache tiene históricos y nginx solo logs activos, elige Apache `access_log` / `access_ssl_log`. En igualdad de disponibilidad prefiere nginx. El informe muestra la fuente elegida y nunca suma ambas capas.

En históricos lee primero las rotaciones numeradas en orden numérico (`.1` antes de `.2` y `.10`), después `.processed` sin número y finalmente los activos. La numeración no demuestra qué fecha contiene un archivo: las fechas se filtran en cada línea. En modo muestra el presupuesto puede impedir llegar a rotaciones antiguas; el modo continuo sigue tras descansar. Esto no recupera logs borrados. Incluye variantes `.processed`, `.N`, `.processed.N` y `.gz`. Evita sumar dos veces un mismo inode/hardlink. Copias distintas que contengan eventos repetidos pueden producir duplicados; una rotación concurrente también puede omitir o repetir eventos. No deduplica por contenido porque dos peticiones legítimas pueden ser idénticas.

Los rankings mantienen hasta 2000 rutas distintas y agrupan las posteriores en `[otras rutas: límite de memoria]`. Por tanto, con alta cardinalidad el top es de las rutas conservadas y su grupo de desbordamiento, no un ranking exacto de todas las URLs.

## Fail2Ban y señales de tráfico sospechoso

**Al indicar un dominio o exportar con `--report`/`--send`**, lee `/var/log/fail2ban.log` y sus variantes `.N` / `.gz`, sin ejecutar `fail2ban-client`, abrir su socket, modificar jails o bloquear/desbloquear direcciones. En la vista global normal no lo lee ni muestra columnas de F2B. Usa `--fail2ban-log /ruta/al/archivo` si está en otra ubicación, o `--no-fail2ban` para omitirlo. Si el servicio envía solo a journald/syslog y no hay archivo compatible, muestra N/D; no cambia el destino del log ni consulta el journal automáticamente.

El presupuesto de Fail2Ban sigue limitado al menor de `--seconds` y 30 segundos, y al menor de `--max-mib` y 16 MiB, incluso en modo continuo; puede aparecer PARCIAL sin detener el análisis de accesos. Conserva como máximo 20 000 IP únicas y 100 jails más un grupo de otras. Aplica las mismas pausas y límites de línea, y detiene su muestra por carga. Los contadores son eventos Ban e IP **observados**; cobertura incompleta, logs duplicados o retención pueden alterar los totales. No cuenta `Unban`, `Restore Ban` ni mensajes `Found`. No verifica que el firewall aplicase correctamente el bloqueo y no enumera bloqueos activos anteriores a la fecha.

Los registros Fail2Ban sin offset se filtran por su fecha local escrita: se presupone la misma zona que has elegido para analizar accesos. Si la zona del servidor difiere, la coincidencia diaria cerca de medianoche puede ser inexacta. Una IP bloqueada en SSH puede aparecer también visitando una web; la columna de coincidencias no afirma que esa web generara el bloqueo.

Cada dominio muestra 4xx/5xx, accesos a rutas sensibles y pico observado de peticiones por minuto. Marca **REVISAR** si encuentra cualquiera de estos umbrales orientativos:

- Al menos 20 accesos a rutas sensibles con respuesta 4xx (el login legítimo con respuesta 200 ya no activa esta condición).
- Al menos 100 peticiones observadas con 50% o más de respuestas 4xx.
- Al menos 20 peticiones observadas con 10% o más de respuestas 5xx.

El pico de peticiones se informa como volumen de actividad, pero ya no activa REVISAR por superar 300/min.

No confirma ataques ni calcula una probabilidad. Un bot legítimo puede tener mucho tráfico; 4xx/5xx pueden tener causas normales o fallos de la aplicación. Los límites de lectura pueden ocultar picos. Los minutos repetidos por cambio horario se distinguen por offset. Al consultar un dominio, añade las diez IP con más peticiones y las rutas sensibles más consultadas. Conserva como máximo 2000 IP y agrupa las restantes; no hace resolución DNS ni confía en cabeceras X-Forwarded-For. Una dirección registrada puede pertenecer a CDN/proxy. **No bloquees una IP solo por este informe.**

## Límites operativos

- Solo abre logs con lectura. El modo normal no escribe archivos. `--report`/`--send` escriben únicamente sus HTML privados en `reports/`; no crean cachés ni bases de datos.
- No instala paquetes, crea cron, cambia Plesk/PHP, permisos, firewall, servicios ni bases de datos de las webs.
- Sin peticiones HTTP ni análisis simultáneo de dominios. Solo `--send` ejecuta el comando fijo de correo ya instalado; no usa shell. No ejecutes varias copias a la vez: esta versión no impide ejecuciones simultáneas independientes.
- Prioridad CPU nice 19 y límite de espacio de direcciones virtual de 128 MiB para el propio proceso. Este límite no equivale a una promesa de RAM RSS exacta. Un proceso puede terminar sin informe si agota memoria.
- En modo continuo espera si la carga media de un minuto supera 1 por CPU lógica o quedan menos de 256 MiB de `MemAvailable`, y retoma al recuperarse. Comprueba cada 100 fragmentos. En `--sample`/Fail2Ban detiene su muestra y comprueba cada 250 fragmentos. Son guardas orientativas del host, no métricas por dominio ni garantías de impacto cero; pueden no reflejar límites de contenedores/cgroups.
- Inventario limitado a 10 000 entradas y 15 segundos, 4096 entradas por directorio de logs, 128 archivos de acceso por dominio. Una carpeta enorme puede requerir consultar un dominio concreto.
- No sigue enlaces simbólicos en la ruta ni en archivos de logs; usa descriptores y `O_NOFOLLOW`. Rechaza dispositivos y FIFOs. Un dominio con logs enlazados puede necesitar un diseño de acceso distinto, no cambiar permisos automáticamente.
- Líneas de hasta 16 KiB; descarta fragmentos excesivos/incompletos y avisa. El tiempo es un límite cooperativo entre lecturas: un disco bloqueado puede tardar más en responder.
- Elimina query strings, limita rutas, oculta identificadores largos y correos evidentes y neutraliza controles de terminal. Una ruta puede seguir conteniendo datos personales: trata la salida como información privada.

## Verificación realizada

En Windows/Python 3.14: clasificación, cambios de día por offset, fechas inválidas, redacción, cardinalidad, selección de capa, gzip, presupuestos, duplicados por inode, guardas, ranking, columnas, señales y parser Fail2Ban. Una prueba de integración con descriptores adaptados verifica lectura histórica gzip, errores internos y coincidencias con Fail2Ban, y comprueba que los archivos de prueba no cambian. La prueba de enlaces/FIFO requiere Linux y se omite en Windows. No se ha ejecutado esta nueva versión contra tu servidor ni se ha validado el recorrido real de descriptores en Linux en este entorno. No garantiza impacto cero en producción.

Pruebas locales:

```sh
cd /too-custom/audithor
/usr/bin/python3 -B -m unittest -v test_audithor.py
```

El test crea únicamente archivos temporales propios y los elimina al finalizar. No necesita leer los logs del servidor. Para una primera lectura real acotada, empieza con un solo dominio y `--sample --seconds 2 --max-mib 1 --no-fail2ban`.

Esta revisión es **0.7.0**. Comprueba que subiste el archivo nuevo con `python3 -I -B audithor.py --version`. Las pruebas incluyen continuidad entre tandas, espera por carga, bloqueo antes del sexto dominio hasta escribir `start`, HTML escapado, informes parciales sin envío y un único mensaje MIME dirigido al destinatario solicitado. Las pruebas de correo usan un proceso simulado: no se ha enviado un correo real desde este entorno. La creación privada mediante descriptores y su prueba de enlaces requieren Linux y se omiten en Windows, junto con la prueba original de logs.

Referencias de formatos y funciones: [logs de Plesk](https://support.plesk.com/hc/en-us/articles/12377744787991-Plesk-for-Linux-services-logs-and-configuration-files), [límites de recursos de Python](https://docs.python.org/3/library/resource.html), [lectura gzip](https://docs.python.org/3/library/gzip.html), [eventos de acciones de Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/fail2ban/server/actions.py).
