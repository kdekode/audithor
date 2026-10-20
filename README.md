# Audithor 0.12.1

La versión 0.12.1 corrige el error `NameError: name 'args' is not defined` al arrancar. Conserva los límites de CPU, memoria y tiempo; añade pruebas del arranque protegido también en Windows.

Creado por **steev anderson**.

Para echar un vistazo al tráfico de las webs de un servidor Linux con Plesk, sin abrir los logs uno por uno. Ayuda a encontrar errores, URLs con mucho movimiento y cosas que merezca la pena revisar.

Necesita **Python 3.9 o superior**, sin librerías externas. Lee los archivos que ya existen: no visita las webs, no bloquea IP ni cambia servicios o configuraciones.

La versión 0.11 añade IP únicas, señales por comportamiento y desglose de rutas sensibles. Un User-Agent Chrome/Firefox se muestra como **navegador aparente**, nunca como prueba de humanidad. Ahora también impide ejecuciones simultáneas y pone límites totales al recorrido completo.

La 0.12 añade `--watch`: vigilancia **manual y temporal de un solo dominio**, con incidencias saneadas en SQLite. No instala ni activa nada por su cuenta.

## Cómo usarlo

Sube los archivos a una carpeta privada fuera de las webs, como `~/tools-idx/audithor/`, y ejecuta desde ahí:

```bash
python3 -I -B audithor.py                       # hoy
python3 -I -B audithor.py --yesterday           # ayer
python3 -I -B audithor.py --week                # hoy y los seis días anteriores
python3 -I -B audithor.py --date 2026-10-18      # una fecha concreta
```

`-I` aísla Python de configuraciones de importación externas y `-B` evita crear archivos de bytecode. Si lo ejecutas como root, la carpeta y el código no deben ser modificables por las cuentas de las webs.

Va **dominio a dominio** y muestra una fila al terminar cada uno. Después de 70, si quedan más, pide escribir `start` para seguir. Con `q` terminas; Enter solo no inicia otra tanda.

Al acabar repite la tabla **de más a menos peticiones**, usando los resultados que ya tiene. No vuelve a leer los logs para ordenarla.

Después añade **DOMINIOS QUE REQUIEREN ATENCIÓN**, con prioridad por salud, impacto potencial y tráfico sospechoso. El detalle explica qué ha visto, qué podría estar pasando y qué revisar en Plesk. El HTML incluye lo mismo.

## Vigilar un dominio en directo con --watch

```bash
python3 -I -B audithor.py dominio.com --watch
```

Solo trabaja mientras ese comando está abierto. Empieza al **final de los archivos existentes**, no recorre históricos y no ejecuta `--full`. Termina con Ctrl+C o al llegar a sus límites. Por defecto dura como máximo unos 15 minutos; no se reinicia ni se reanuda automáticamente al cerrar SSH.

Sube también **`audithor_watch.py`** junto a `audithor.py`. El módulo se carga desde esa carpeta sin añadir directorios de importación a Python. `sqlite3` y `ctypes` son de la biblioteca estándar; si no están disponibles, la vigilancia se niega a arrancar. No hace instalaciones.

### Qué logs utiliza

Solo abre nombres activos dentro de `/var/www/vhosts/system/DOMINIO/logs`, respetando `--root` si lo cambias:

- Errores: `proxy_error_log` y `error_log`.
- PHP, si existen allí: `php_error.log`, `php_error_log`, `php_errors.log`, `php-fpm.log` y `php_fpm_error.log`.
- Accesos: prefiere `proxy_access_log`/`proxy_access_ssl_log`; si no existen al arrancar, elige `access_log`/`access_ssl_log`. Mantiene esa capa durante la sesión para no sumar Apache y nginx.

No busca por `httpdocs`, no sigue enlaces simbólicos ni lee logs globales de PHP-FPM/MySQL de otros clientes. Si PHP solo escribe en un log global o en otra ruta, ese contenido queda fuera de cobertura. Muchos errores PHP ya aparecen en el `error_log` de Apache. Lo que no exista o no sea accesible se registra como aviso; si no puede abrir ningún log, termina.

Usa inotify si Linux lo permite, con comprobaciones de archivos entre ciclos. Si no está disponible, revisa los mismos nombres cada dos segundos. Incluso con inotify espera **al menos dos segundos** entre ciclos: una ráfaga de avisos no crea un bucle sin pausa.

### Qué guarda y qué descarta

Registra HTTP 500/502/503/504, PHP Fatal, excepciones, límites de memoria o PHP-FPM, problemas de permisos, timeouts y errores SQL **ya presentes en los logs**. Cuenta accesos en memoria para avisar si observa al menos 600 peticiones del dominio en un minuto, pero no almacena las peticiones normales. Ese umbral es una señal de volumen, no un ataque demostrado.

Agrupa por minuto, tipo, servicio y evidencia saneada; la frecuencia cuenta mensajes/incidencias observados, no fallos únicos demostrados. No relaciona un error PHP con una petición de acceso solo porque tengan horas parecidas. Una ruta HTTP solo se conserva si forma parte de ese registro; si no, figura «sin relación HTTP demostrada».

Por privacidad, guarda marcadores estructurados, código HTTP, SQLSTATE si aparece y **solo el nombre PHP y la línea** cuando estén explícitos. No guarda SQL, mensajes libres, argumentos, cookies, contraseñas ni trazas. Elimina consultas de las URLs y sustituye segmentos variables por `:segmento`; conserva unas pocas rutas conocidas, como `/wp-login.php` o `/api`. Esto reduce detalle a propósito. No descarga contenido ni consulta bases de datos de clientes.

Sigue rotaciones por inode y conserva brevemente el descriptor anterior para drenar líneas pendientes. Detecta truncamientos y sustituciones de contenido con tamaño y una pequeña huella del final leído. Para copias tras rotación/truncamiento compara las últimas 256 huellas por archivo: descarta posibles repeticiones y deja constancia. **No es deduplicación perfecta**: un mensaje legítimo idéntico puede coincidir y las copias antiguas pueden escapar a esa ventana. Las escrituras tardías en un descriptor ya cerrado, rotaciones muy rápidas y relojes discrepantes también pueden causar huecos.

### SQLite privado y cobertura

Guarda en `/root/tools-idx/audithor/data/audithor.sqlite` si esa es la carpeta del proyecto. Crea `data/` con 700 y sus archivos con 600; rechaza carpetas/archivos públicos, de otro usuario o enlazados, sin cambiar permisos existentes. `data/` está en `.gitignore` y debe seguir fuera de cualquier web.

Solo `--watch` escribe incidencias. La consulta posterior abre SQLite en modo de lectura. Guarda inicio, último latido, fin, motivo de cierre, fuentes detectadas, pausas y pérdidas conocidas. Si el proceso muere sin poder cerrar, la sesión queda sin fin: el último latido **no demuestra cobertura posterior**. Un corte eléctrico o SIGKILL puede perder lo que aún no estaba confirmado en SQLite.

| Límite de vigilancia | Valor |
|---|---|
| Archivos abiertos | Hasta 16, incluidos descriptores de rotaciones. |
| Lectura por ciclo | Hasta 64 KiB de contenido; 16 KiB si la carga supera 0,8 por CPU. Hay pequeñas lecturas adicionales de huellas y metadatos. |
| Procesamiento por ciclo | Objetivos de 50 ms CPU, 200 ms reales y 1000 líneas; más las operaciones de cierre/escritura. Se conservan los límites globales del kernel. |
| Línea / prefijo pendiente | Hasta 8 KiB; las líneas mayores se descartan con aviso. |
| Incidencias / cola | 120 por minuto y hasta 128 grupos en memoria; el exceso se descarta y se registra. |
| Atraso por archivo | Si supera 1 MiB, salta al final y registra los bytes afectados. |
| Escritura | Cada cinco segundos y al cerrar; espera SQLite de 100 ms y presupuesto de sentencia de 200 ms. Tres fallos consecutivos detienen la vigilancia. |
| SQLite | Hasta 8 MiB de base principal, con journal temporal adicional; caché de 512 KiB y sin WAL ni VACUUM automático. |
| Retención | Hasta siete días consultables; purga incremental durante `--watch`. Topes de 10.000 grupos, 500 sesiones y 2000 avisos pueden reducir ese período. Apagado no ejecuta purgas ni tareas en segundo plano. |

Los bytes afectados pueden ser una cota del bloque descartado; las incidencias desconocidas no se inventan como un recuento exacto. Se informa también de pérdidas de avisos inotify, líneas no interpretadas y trazas descartadas. Una purga lógica no reduce necesariamente el tamaño físico del archivo: las páginas se reutilizan.

Si la carga supera una CPU por núcleo, pausa el procesamiento, descarta el atraso con aviso y espera cinco segundos entre comprobaciones. Si dura 30 segundos, termina. Con menos de 256 MiB disponibles termina directamente. Las comprobaciones que no se pueden realizar también detienen el proceso. Esto prioriza las webs sobre conservar todas las incidencias.

El bloqueo de watch es **no bloqueante y por dominio**, dentro de `data/`; no usa el bloqueo general de `/tmp`. Solo protege ejecuciones que usen esta misma carpeta de datos. Los bloqueos vacíos permanecen, pero el kernel los libera al terminar: no hay procesos residentes. No arranques varios monitores por probar; empieza con uno.

Se mantienen 128 MiB de memoria virtual principal, el presupuesto CPU del kernel, el temporizador real y los límites acumulados de lectura. Además limita el tamaño de archivos propios a 16 MiB. Los presupuestos de ciclo son comprobaciones cooperativas, no cuotas instantáneas del kernel. Un disco en espera no interrumpible puede tardar en responder: no se promete consumo cero ni un cierre instantáneo en cualquier fallo del sistema.

### Prueba manual de cinco minutos, sin tocar servicios

Desde el servidor, después de subir los archivos:

```bash
cd /root/tools-idx/audithor
python3 -I -B audithor.py --version
python3 -I -B audithor.py dominio.com --watch --watch-seconds 300 --run-seconds 330
```

Deja que llegue el tráfico normal. **No provoques errores, no añadas líneas a logs de producción ni hagas peticiones de carga.** Puedes pulsar Ctrl+C antes: intenta guardar lo pendiente y cerrar SQLite. El proceso no activa cron, servicios, timers de systemd, puertos ni endpoints.

Después consulta hoy:

```bash
python3 -I -B audithor.py dominio.com
```

Verás «INCIDENCIAS GUARDADAS POR --watch», con frecuencia, horas, gravedad, servicio, archivo/línea, ruta saneada, evidencia, recomendaciones y cobertura. Si no hubo errores durante esos cinco minutos, lo esperable es una sesión sin incidencias, no una certificación de salud del dominio.

Para sesiones que realmente ocurrieron ayer:

```bash
python3 -I -B audithor.py dominio.com --yesterday
```

La vigilancia de hoy no puede reconstruir ayer. La consulta muestra hasta 50 grupos, 20 sesiones y 50 avisos del período, también en HTML al pedir el informe de ese dominio. `obs.` indica hora de observación porque no se reconoció la fecha del mensaje. Los mensajes sin offset usan la zona elegida; comprueba que coincida con el servidor.

`--watch` no se combina con históricos, `--full`, `--report`, inspecciones ni Fail2Ban activo. `--watch-seconds` fija su duración manual, de 1 a 3600 segundos, y el límite global `--run-seconds` sigue aplicándose. Final manual/Ctrl+C: salida 0; problemas de SQLite o ausencia de logs: salida 1; presión o límites de seguridad: salida 75. Si el kernel mata el proceso, la salida puede ser distinta y la sesión quedar sin cierre.

**Sin sesión guardada o fuera de los intervalos registrados, la cobertura es desconocida.** La retención también puede haber borrado datos. Audithor no arranca ningún monitor automáticamente ni intenta recuperar el tiempo en el que no estuvo activo.

## Qué significa cada cosa

| Columna | Qué estás viendo |
|---|---|
| PETICIONES | Solicitudes leídas para la fecha elegida. Una imagen o un CSS también cuenta; no son visitantes. |
| MiB | Contenido enviado según el log. No es consumo de RAM ni CPU. |
| IP ÚNICAS | Direcciones distintas observadas en esa web y período; `~` significa aproximación. No son visitantes. |
| BOTS / NAV. / DESC. | Automatización declarada en el User-Agent, navegador aparente y tráfico sin identificar. Son etiquetas del log, no probabilidades de humanidad. |
| 4xx | Respuestas como 403 o 404: solicitudes rechazadas o recursos no encontrados. |
| 5xx | Respuestas como 500 o 503: errores del servidor. |
| PICO/MIN | El minuto con más peticiones de los que se han leído. |
| ESTADO | Volumen orientativo y avisos de la lectura. |

En ESTADO, **M** significa muestra; **A**, avisos adicionales; **REV:n**, cuántas condiciones de revisión se han activado. **SIN FECHA** significa que no se encontraron accesos de esa fecha en la lectura, no que el tráfico fuera cero.

El pico se etiqueta como BAJA (<60/min), MODERADA (60–599), ALTA (600–2999) o MUY ALTA (3000 o más). No compara con el tráfico habitual de esa web ni confirma un ataque.

Marca revisión con al menos 20 accesos a rutas sensibles rechazados con 4xx, un 50% de 4xx sobre al menos 100 peticiones, o un 10% de 5xx sobre al menos 20. Puede ser un fallo de la web, tráfico legítimo o algo sospechoso: toca mirar el detalle.

## El diagnóstico nuevo

Son tres preguntas distintas:

| Indicador | Cómo leerlo |
|---|---|
| SALUD WEB | OK, REVISAR o CRÍTICO según cantidad y proporción de 5xx. Con menos de 20 peticiones queda INDETERMINADO. |
| TRÁFICO SOSPECHOSO | BAJO, MODERADO o ALTO según accesos sensibles rechazados, automatización probable y picos sostenidos con errores. Muchos bots o muchos 404, por sí solos, no bastan para marcar ALTO. |
| IMPACTO POTENCIAL | BAJO, POSIBLE, ALTO POTENCIAL o NO DETERMINADO. Usa duración explícita, picos sostenidos con errores de backend o mensajes sobre límites alcanzados. No mide CPU ni RAM por web. |

**OK o BAJO solo hablan de lo leído.** Si no hay accesos del período, salud y tráfico quedan INDETERMINADOS. Si faltan métricas de coste, el impacto queda NO DETERMINADO. CRÍTICO describe errores de la web; no significa que esa web esté tirando el servidor.

El detalle separa 400, 401, 403, 404, 408, 429, 500, 502, 503 y 504, y agrupa los demás errores. Los porcentajes usan todas las peticiones leídas, también las correctas. Muestra rutas e IP con errores, los minutos con más errores y cuántos coinciden con el pico de tráfico.

Un 404 de una imagen puede ser barato; uno resuelto por WordPress puede ejecutar PHP. Audithor diferencia el aspecto estático/dinámico de las rutas como pista, **sin dar por probado quién respondió ni cuánto costó**. Los parámetros de URL no se guardan y se ocultan patrones de tokens en rutas; el HTML sigue siendo privado porque puede incluir IP y otros datos de las rutas.

Solo interpreta duración si el formato combined ya lleva un sufijo explícito `request_time=2.500` en segundos. No adivina columnas ni modifica el formato de tus logs. Esa duración incluye esperas y envío al cliente: no es tiempo de CPU. Sin ese campo, no inventa métricas.

La confianza baja si es muestra o hay lecturas incompletas. No se extrapola al día entero. En HTML se enseñan hasta 20 minutos con errores y en consola 10; no es una distribución completa de todo el día.

### Ajustar los umbrales

Puedes cambiarlos para esa ejecución, sin editar archivos:

```bash
python3 -I -B audithor.py --yesterday --threshold health_review_pct=10
python3 -I -B audithor.py ejemplo.com --threshold sustained_rpm=900 --threshold slow_seconds=3
```

| Umbrales | Valores iniciales |
|---|---|
| Salud: `health_min`, `health_review_count`, `health_review_pct` | 20 peticiones; al menos 5 errores y 5% para REVISAR. |
| Salud: `health_critical_count`, `health_critical_pct` | Al menos 20 errores y 20% para CRÍTICO. |
| Exploración: `sensitive_review`, `sensitive_high`, `bot_pct` | 20 rechazos sensibles para MODERADO; 100 y al menos 50% de bots para ALTO. |
| Picos: `sustained_rpm`, `sustained_minutes`, `gateway_count` | 600/min durante 3 minutos consecutivos y al menos 5 respuestas 502/503/504 en el período son señal de impacto POSIBLE. |
| Duración: `slow_seconds`, `slow_pct`, `timing_min`, `timing_coverage_pct` | Lento desde 2 s; al menos 20 duraciones y cobertura del 80%. Con 50% de lentas, impacto POSIBLE; unido a los picos sostenidos y errores anteriores, ALTO POTENCIAL. |
| Coincidencias: `shared_domains`, `shared_5xx_count`, `shared_5xx_pct` | 2 dominios en el mismo minuto, cada uno con al menos 5 errores 5xx y 10% de errores; también busca picos y errores de gateway coincidentes. |

Con duración suficiente, ningún acceso lento y sin errores de gateway ni mensajes de límites, el impacto se etiqueta BAJO por las señales observadas de latencia. No certifica un consumo bajo. Una señal explícita de límites PHP-FPM/Apache/backend basta para POSIBLE. Tráfico ALTO también puede marcarse con los picos sostenidos anteriores, al menos 50% de bots y 50% de 4xx.

Todos los nombres y valores aparecen en `--help`. Los porcentajes admiten valores mayores que 0 y hasta 100; los contadores son enteros positivos hasta un millón, las rachas hasta 60 minutos, la duración hasta 600 segundos y los dominios compartidos entre 2 y 8. Los límites críticos no pueden ser menores que los de revisión. Estos ajustes afectan al diagnóstico nuevo; la columna ESTADO conserva sus señales anteriores.

### Cuando coinciden varias webs

Si varios dominios tienen errores o picos en el mismo minuto, aparece **POSIBLE INCIDENCIA COMPARTIDA DEL SERVIDOR**. Es una pista para revisar servicios comunes, no una conclusión. Sin una línea base, tampoco se puede afirmar que haya aumentado el tráfico o los errores.

Solo cruza accesos del mismo recorrido y raíz de logs. No importa informes anteriores ni mezcla servidores. Guarda como máximo 2048 minutos relevantes, 8 dominios por grupo y muestra 20 coincidencias. Los mensajes internos se resumen por dominio cuando se leen, pero no se correlacionan entre webs porque no siempre tienen hora y zona fiables.

Si hay señales de exploración, propone investigar rutas, tasas por IP y posibles intentos de fuerza bruta. Las sugerencias de Cloudflare son para revisar manualmente: no crea reglas ni bloquea IP. Evita aplicar desafíos generales a WordPress, WooCommerce, APIs o paneles. Los fallos internos que causan 5xx requieren revisar la aplicación o el backend.

## Recursos actuales, aparte del historial

```bash
python3 -I -B audithor.py --resources
```

Muestra una instantánea **actual** y termina sin analizar dominios: carga, memoria disponible, presión PSI si el kernel la ofrece, contador OOM desde el arranque y procesos observados de PHP-FPM, MySQL/MariaDB y nginx/Apache.

No lo relaciona con errores de ayer. El contador OOM no dice cuándo pasó ni qué proceso fue. Contar procesos tampoco demuestra saturación de pools. Máximo 0,5 segundos cooperativos, 256 KiB y 512 procesos; si no hay permisos o archivos, muestra N/D o lectura parcial.

Para conocer colas y límites de pools harían falta sus logs o métricas de estado ya disponibles. Audithor no activa la página de estado de PHP-FPM, no consulta endpoints ni sockets SQL, no lee credenciales y no instala monitorización. Esas comprobaciones quedan para Plesk; las métricas históricas de recursos no están disponibles.

## Mirar una web con más calma

```bash
python3 -I -B audithor.py ejemplo.com --yesterday
python3 -I -B audithor.py ejemplo.com --week
```

Aquí salen explicaciones, URLs con más peticiones y transferencia, IP, errores, rutas sensibles y los avisos completos.

### IP únicas y automatización

El conteo es exacto hasta 1024 IP distintas **dentro de lo leído**. Después pasa a HyperLogLog con 2048 registros fijos y se marca `~`. Su error típico ronda el 2,3%, pero no es una garantía para un resultado concreto. Guarda un contador total y otro para cada apariencia de User-Agent. Una misma IP puede aparecer en varias categorías: no se suman para calcular el total.

La memoria de estos contadores está acotada aunque aparezcan millones de IP. Sigue siendo una muestra de los logs: ni un número exacto de direcciones observadas equivale al total diario ni una IP equivale a una persona. NAT y CDN pueden juntar usuarios en la misma dirección.

Para encontrar automatización disfrazada de navegador comprueba, por IP:

- Al menos 20 accesos sensibles y 10 respuestas 403/404.
- Una ráfaga de al menos 120 peticiones/minuto junto con 50 repeticiones de una ruta.
- Una racha observada de 20 respuestas 403/404 dentro de un minuto y al menos 10 rutas distintas en la lectura de esa IP.

Son señales para investigar, no un veredicto: un proxy compartido o una aplicación legítima también pueden producirlas. Se rastrean las primeras 1024 IP, hasta 32 rutas y 64 minutos por IP. Al superar un límite avisa de que la detección es parcial; enseña hasta 20 hallazgos. Las rachas siguen el orden leído por IP, no reconstruyen sesiones reales ni unen secuencias entre minutos.

En el detalle separa solicitudes de automatización declarada, solicitudes no declaradas de IP con comportamiento sospechoso y el resto indeterminado. Son conteos observados, sin porcentajes de probabilidad. La columna NAV. sigue describiendo la apariencia del User-Agent, aunque esa IP tenga señales sospechosas.

### Rutas sensibles con respuesta 200

Cada ruta incluye total, 200, 401, 403, 404, otros códigos y hasta cinco IP solicitantes con sus conteos. Guarda hasta 64 rutas y las primeras 8 IP por ruta; si se supera el límite, el ranking es parcial. Da prioridad a archivos internos como `.env`, `.git` o `wp-config.php` que devuelvan 200 y puede sustituir una ruta de menor prioridad para conservarlos.

**Un 200 no confirma una exposición.** Puede ser una página de error personalizada o una respuesta del front controller. Compara tamaños observados de 200 y 404 como pista, pero no verifica cuerpos. La comprobación del archivo y de sus reglas queda para Plesk: Audithor no descarga contenido ni hace peticiones adicionales.

También lee **Fail2Ban** desde `/var/log/fail2ban.log`. Cuenta eventos `Ban` y cruza sus IP con las vistas en esa web durante el período. La coincidencia no demuestra que esa web causara el bloqueo ni que la IP siga bloqueada ahora. No se conecta al servicio.

Elige archivos por fechas de extractos: `.1.gz` no tiene por qué ser ayer. Muestra los archivos seleccionados, los MiB leídos y las fechas encontradas. Puedes cambiar la ruta con `--fail2ban-log /ruta/al/log` u omitirlo con `--no-fail2ban`.

La tabla global normal no lee Fail2Ban ni los mensajes internos de errores. RAM y CPU históricas por dominio tampoco aparecen: estos logs no permiten reconstruirlas.

### Fail2Ban activo, opcional

```bash
python3 -I -B audithor.py ejemplo.com --yesterday --fail2ban-active
```

Además del historial solicitado, consulta el **estado actual**, con su propia fecha, usando únicamente `status` y `status NOMBRE_JAIL` de `/usr/bin/fail2ban-client`. No usa shell ni ejecuta órdenes para cambiar bloqueos. Requiere que el cliente ya exista, pertenezca a root y que tu usuario tenga permiso sobre el socket local; no cambia permisos ni instala nada.

Tiene un máximo de 3 segundos cooperativos para todas las consultas, 32 jails, 64 KiB de salida por consulta y 5000 IP únicas. Muestra hasta 20 IP por jail. El único proceso hijo se limita a 1 segundo CPU y 64 MiB de memoria virtual y se termina si excede tiempo/salida; esos 64 MiB son adicionales al límite del proceso principal, no una reserva de RAM. Si no hay acceso o no entiende la respuesta, muestra N/D o parcial. Las consultas no son una instantánea atómica: los bloqueos pueden cambiar mientras lee.

El estado ACTIVO AHORA no se presenta como bloqueo de ayer. Las coincidencias con IP del historial tampoco demuestran qué web originó el bloqueo. `--no-fail2ban` omite solo el historial; la consulta activa requiere siempre su opción explícita.

Etiqueta coincidencias con las redes oficiales de Cloudflare incluidas y verificadas el **2026-10-20**. No descarga listas durante la ejecución. Esa IP puede ser un proxy compartido, no el atacante; una dirección sin etiqueta tampoco demuestra que no haya un proxy o una red nueva de Cloudflare. No confía automáticamente en cabeceras reenviadas.

## Consumo y tiempo

Por defecto lee una **muestra de hasta 5 segundos y 8 MiB por dominio**. Con `--week` mantiene ese presupuesto, no lo multiplica por siete. Los números pueden cubrir solo parte del día o de la semana.

Lee poco a poco, sin análisis de dominios en paralelo ni cargar archivos enteros en RAM. Reduce el ritmo con carga alta y aplaza el trabajo si quedan menos de 256 MiB disponibles. Si la carga media supera el mayor de 4 o dos veces el número de CPU lógicas, también aplaza la vista rápida.

Para ir más despacio, añade `--gentle`. Los objetivos de porcentaje de CPU y ritmo de disco siguen siendo reguladores cooperativos, no cuotas del kernel. Hay además límites efectivos independientes:

| Protección | Valor inicial |
|---|---|
| Memoria del proceso principal | 128 MiB de espacio virtual mediante RLIMIT_AS, o el límite existente si es menor. No es una reserva ni una medida de RAM residente. |
| Tiempo CPU | 30 segundos acumulados para todo el proceso, más redondeo a segundos y hasta un segundo de gracia del kernel. RLIMIT_CPU termina el proceso si no puede recuperarse. No promete un porcentaje instantáneo de CPU. |
| Tiempo real | Temporizador de 900 segundos para toda la ejecución, incluidas esperas y el tiempo que tardes en escribir `start`. Cada dominio también tiene temporizador: presupuesto rápido +4 s; en completo, límite del dominio +4 s para terminar de informar. |
| Lectura acumulada | 256 MiB de entrada bruta y, por separado, hasta 256 MiB descomprimidos/contabilizados. Se limita la entrada antes de buffer y gzip. |
| Ejecución única | `flock` exclusivo en `/tmp/audithor.lock`, también para diagnóstico y recursos actuales. No inicia el trabajo si no puede adquirirlo de forma segura. |

El archivo de bloqueo es privado (600), debe pertenecer al usuario que ejecuta Audithor y no admite enlaces ni permisos de grupo/otros. Se deja vacío al terminar para evitar carreras entre ejecuciones; el kernel libera el bloqueo incluso si el proceso muere. No es un servicio residente. Si pertenece a otro usuario, Audithor se niega a usarlo: no lo borra ni cambia sus permisos automáticamente.

Al alcanzar un límite de seguridad se detiene con código 75 y resultados parciales. Si el kernel debe terminarlo directamente, la salida puede ser distinta y el HTML quedar interrumpido. Un proceso en espera de disco no interrumpible puede tardar en recibir una señal: no hay garantía de impacto cero ni de detener un bloqueo del kernel en un instante exacto. No se cambian cgroups ni ajustes del servidor.

El detalle añade hasta 2 segundos/2 MiB para errores internos y hasta 3 segundos/2 MiB para Fail2Ban. Este último se lee una sola vez por ejecución.

Para ampliar una lectura concreta:

```bash
python3 -I -B audithor.py ejemplo.com --yesterday --seconds 20 --max-mib 32
```

Existe `--full` para recorrer más archivos de la capa elegida, pero **ya no tiene recorrido ni espera ilimitados**. Conserva las tandas y se detiene por dominio a los 30 segundos/64 MiB por defecto, además de los límites globales. Espera por carga solo dentro de esos presupuestos. Fail2Ban conserva su límite histórico de 3 segundos/2 MiB.

Para ampliar explícitamente un recorrido concreto:

```bash
python3 -I -B audithor.py ejemplo.com --yesterday --full --allow-long-scan --seconds 60 --max-mib 128
```

`--allow-long-scan` autoriza valores por encima de 30 s/64 MiB; no elimina las protecciones. `--run-seconds`, `--cpu-seconds` y `--run-mib` permiten ajustar los límites globales; aumentarlos sobre 900 s/30 s/256 MiB también requiere esa autorización. Sus máximos son 3600 s reales, 120 s CPU y 2048 MiB por contador. La memoria principal permanece limitada a 128 MiB.

## Si faltan datos

```bash
python3 -I -B audithor.py ejemplo.com --yesterday --inspect-logs
python3 -I -B audithor.py --diagnose
python3 -I -B audithor.py --version
```

`--inspect-logs` muestra archivos y fechas de extractos pequeños, sin IP ni URLs. `--diagnose` consulta carga y memoria sin abrir logs. Si una opción no se reconoce, comprueba que has subido la versión actualizada.

Busca en `/var/www/vhosts/system/DOMINIO/logs`. Usa una sola capa, Apache o nginx, para evitar sumar las mismas peticiones dos veces. Admite `.processed` y rotaciones gzip; para fechas pasadas incluye gzip automáticamente. Para hoy puedes añadir `--gzip`.

La zona por defecto es `Europe/Madrid`; se cambia con `--timezone`. Fail2Ban y los errores internos usan la fecha local escrita en el log: conviene que coincida con la zona del servidor.

**No encontrar datos no demuestra que no hubiera tráfico.** Puede faltar historial, agotarse el presupuesto o no elegirse el archivo adecuado. Incluso una lectura completa depende de los registros que se hayan conservado.

La cobertura del período se indica como **DESCONOCIDA** salvo que hubiera datos que demostraran lo contrario. Enseña en cuántas fechas y minutos se observaron peticiones, sin convertirlo en porcentaje de tráfico cubierto. Encontrar accesos el primer y último día no demuestra que se haya leído lo de en medio.

Revisa extractos de los textos HTTP/HTTPS antes de gastar el presupuesto en gzip. Aunque un `.processed` abarque la fecha, considera gzip que empiezan dentro del período; si solo empiezan antes y el texto cubre el intervalo, puede omitirlos y lo advierte. El final de gzip no se conoce sin recorrerlo. Los intervalos, rotaciones solapadas o entradas fuera de orden siguen siendo una limitación. Nunca suma Apache y nginx para una misma web; deduplica hardlinks por inode, pero no puede identificar con seguridad copias independientes de los mismos eventos sin confundir peticiones legítimas iguales.

## Guardar un informe

```bash
python3 -I -B audithor.py --yesterday --report
python3 -I -B audithor.py ejemplo.com --week --report
```

Guarda un HTML en `reports/`, junto al script. Con `--report` continúa por todos los dominios seleccionados sin pedir `start`, pero sigue leyéndolos uno a uno.

El informe tiene un límite de 2 MiB y avisa si queda parcial. Puede contener IP y rutas: mantenlo fuera de las webs y de Git. `reports/` ya está en `.gitignore`. Los informes antiguos no se borran solos. No envía correo ni genera PDF.

## Pruebas

```bash
python3 -B -m unittest -q
```

Hay pruebas locales de fechas, selección de logs, límites, tablas, informes y Fail2Ban. Algunas comprobaciones de permisos y enlaces necesitan Linux. Esto no sustituye comprobar los resultados con los logs de tu servidor.

Para 0.12.1: 128 pruebas, 122 correctas y 6 omitidas porque requieren Linux. Las pendientes comprueban descriptores/enlaces/permisos, permisos de informes, límites reales del kernel/bloqueo/temporizador, entrada bruta, privacidad de `data/` e inotify real. Las pruebas de watch usan SQLite y logs temporales: EOF, rotación, truncamiento, copias repetidas, PHP/SQL/nginx/PHP-FPM, secretos, presión, Ctrl+C, cola llena, SQLite lleno/ocupado, retención y ausencia de logs. No se han ejecutado pruebas en los dominios del servidor ni consultas a un Fail2Ban real.

Comparación local con 0.10.0 sobre 12.000 accesos: ambas versiones leyeron 1.396.357 bytes y encontraron las mismas peticiones. Mediana de tres recorridos: 0,5000 s CPU antes y 0,5469 s después; pico de asignaciones Python de 449,9 a 460,8 KiB. Es una prueba pequeña con una IP repetida, lector adaptado a Windows y pausas/estado del host simulados. No mide RSS ni predice el coste con miles de IP; los topes de estructuras y los límites de ejecución controlan esos casos.

Siguen siendo estimaciones: los conteos HLL, las etiquetas de User-Agent, la automatización sospechosa, el impacto potencial, los rankings recortados y las posibles exposiciones. La cobertura diaria/semanal no se extrapola. La integración activa de Fail2Ban necesita validarse con la versión instalada y los permisos reales del servidor.

Referencias para interpretar las métricas: [PSI en Linux](https://docs.kernel.org/accounting/psi.html), [tiempos del log de nginx](https://nginx.org/en/docs/http/ngx_http_log_module.html), [estado de PHP-FPM](https://www.php.net/manual/en/fpm.status.php) y [errores 5xx en Cloudflare](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/).

Protecciones y redes: [RLIMIT en Python](https://docs.python.org/3/library/resource.html), [señales y temporizadores](https://docs.python.org/3/library/signal.html) y [lista oficial de IP de Cloudflare](https://www.cloudflare.com/ips/).

Vigilancia: [inotify y sus límites](https://man7.org/linux/man-pages/man7/inotify.7.html), [SQLite en Python 3.9](https://docs.python.org/3.9/library/sqlite3.html), [tope de páginas SQLite](https://www.sqlite.org/pragma.html#pragma_max_page_count) y [ubicaciones de logs Plesk](https://support.plesk.com/hc/en-us/articles/12377744787991-Plesk-for-Linux-services-logs-and-configuration-files).
