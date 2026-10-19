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
/usr/bin/python3 -I -B /too-custom/audithor/audithor.py ejemplo.com --gentle --seconds 2 --max-mib 1
```

El diagnóstico también acepta `--gentle`. Sin esta opción se aplica una pausa de 1 ms y el mismo umbral de 1 por CPU lógica. Las guardas durante lectura se comprueban cada 250 fragmentos, por lo que en modo lento la detección puede tardar unos 2,5 segundos más la lectura y el procesamiento.

## Uso

Hoy, cinco dominios por tanda, con bloques separados y métricas en columnas:

```sh
/usr/bin/python3 -I -B /too-custom/audithor/audithor.py
```

Primero lee todos los dominios secuencialmente y conserva únicamente un resumen pequeño por dominio. Después muestra el ranking **de más a menos peticiones observadas en la fecha elegida**, desempatando por bytes y nombre. No es un ranking de CPU/RAM. Los presupuestos, históricos ausentes o formatos no interpretados pueden alterar el orden respecto al tráfico real completo.

Enter muestra los cinco siguientes del ranking ya calculado, sin releer sus logs. `q` seguido de Enter termina; Ctrl+C detiene la lectura. Si conecta su salida a una tubería o se ejecuta sin terminal, muestra solo la primera tanda, pero debe analizar todos antes para ordenarlos. Los dominios sin datos de lectura aparecen al final con tráfico N/D; no se interpretan como tráfico cero. Si sube la carga durante el recorrido, detiene la lectura e indica cuántos dominios quedaron pendientes fuera del ranking.

El inventario se recorre inicialmente por modificación de logs para preparar las lecturas; ese orden no determina el ranking final. La espera inicial puede ser de hasta el presupuesto por dominio multiplicado por el número de dominios. No se mantienen tablas de URLs en memoria durante la vista global.

Ayer / fecha histórica / dominio concreto:

```sh
/usr/bin/python3 -I -B /too-custom/audithor/audithor.py --yesterday
/usr/bin/python3 -I -B /too-custom/audithor/audithor.py --date 2026-10-18 --gzip
/usr/bin/python3 -I -B /too-custom/audithor/audithor.py ejemplo.com
/usr/bin/python3 -I -B /too-custom/audithor/audithor.py ejemplo.com --yesterday --gzip
```

Para dedicar hasta media hora a un dominio, conservando lectura secuencial y memoria acotada:

```sh
ionice -c 3 /usr/bin/python3 -I -B /too-custom/audithor/audithor.py ejemplo.com --seconds 1800 --max-mib 1024 --gzip
```

Máximos por dominio: 1–1800 segundos y 1–1024 MiB **descomprimidos**. Por defecto: 30 segundos y 64 MiB. Leerá como máximo unas 1000 líneas/s gracias a una pausa por línea; puede tardar bastante con muchos logs. No reanuda una lectura previa: al repetir el comando empieza de nuevo. Aumenta el presupuesto si el resultado es parcial. `--once` muestra solo los primeros cinco puestos sin interacción, pero la vista global necesita analizar todos los dominios antes de ordenar. Para una prueba acotada a dos segundos en total, indica un dominio concreto y `--no-fail2ban`; en la vista global el límite se aplica a cada dominio y el historial Fail2Ban tiene su propio presupuesto.

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

El nombre ASCII del dominio debe coincidir con su carpeta en `/var/www/vhosts/system`. `--root` permite otra raíz con la misma estructura `dominio/logs`. No usa la API ni la base de datos de Plesk y no hace consultas de red.

Zona por defecto `Europe/Madrid`, modificable con `--timezone`. Los access logs con offset se convierten a esa zona antes de filtrar. Los mensajes internos de nginx/Apache se filtran por su fecha local escrita: al carecer de offset, se presupone que corresponde a la zona elegida. Revisa esta correspondencia si el servidor usa UTC. Solo se interpreta formato combined para accesos y formatos de fecha habituales de nginx/Apache para errores. Líneas no reconocidas generan un aviso en accesos; en logs internos no se contabilizan.

## Históricos y cobertura

Se informa de peticiones **observadas**, fechas encontradas y límites alcanzados. Si no aparecen registros para la fecha, no puede distinguir automáticamente entre ausencia de tráfico, datos eliminados, permisos insuficientes o lectura incompleta. No declara que un día esté completo solo porque haya terminado de leer archivos.

Para hoy, los `.gz` requieren `--gzip`. Para `--yesterday` o una fecha anterior, se incluyen automáticamente y se priorizan archivos rotados sobre los activos. Esto no recupera logs borrados y sigue sujeto a tiempo/bytes. Selecciona una sola capa: nginx `proxy_access_log` / `proxy_access_ssl_log`, o Apache si no existen logs nginx. Incluye variantes `.processed`, `.N`, `.processed.N` y `.gz`. Evita sumar dos veces un mismo inode/hardlink. Copias distintas que contengan eventos repetidos pueden producir duplicados; una rotación concurrente también puede omitir o repetir eventos. No deduplica por contenido porque dos peticiones legítimas pueden ser idénticas.

Los rankings mantienen hasta 2000 rutas distintas y agrupan las posteriores en `[otras rutas: límite de memoria]`. Por tanto, con alta cardinalidad el top es de las rutas conservadas y su grupo de desbordamiento, no un ranking exacto de todas las URLs.

## Fail2Ban y señales de tráfico sospechoso

Lee `/var/log/fail2ban.log` y sus variantes `.N` / `.gz` **una sola vez por ejecución**, sin ejecutar `fail2ban-client`, abrir su socket, modificar jails o bloquear/desbloquear direcciones. Usa `--fail2ban-log /ruta/al/archivo` si está en otra ubicación, o `--no-fail2ban` para omitirlo. Si el servicio envía solo a journald/syslog y no hay archivo compatible, muestra N/D; no cambia el destino del log ni consulta el journal automáticamente.

El presupuesto de esta lectura es el menor de `--seconds` y 30 segundos, y el menor de `--max-mib` y 16 MiB. Conserva como máximo 20 000 IP únicas y 100 jails más un grupo de otras. Aplica las mismas pausas, guardas y límites de línea. Los contadores son eventos Ban e IP **observados**; cobertura incompleta, logs duplicados o retención pueden alterar los totales. No cuenta `Unban`, `Restore Ban` ni mensajes `Found`. No verifica que el firewall aplicase correctamente el bloqueo y no enumera bloqueos activos anteriores a la fecha.

Los registros Fail2Ban sin offset se filtran por su fecha local escrita: se presupone la misma zona que has elegido para analizar accesos. Si la zona del servidor difiere, la coincidencia diaria cerca de medianoche puede ser inexacta. Una IP bloqueada en SSH puede aparecer también visitando una web; la columna de coincidencias no afirma que esa web generara el bloqueo.

Cada dominio muestra 4xx/5xx, accesos a rutas sensibles y pico observado de peticiones por minuto. Marca **REVISAR** si encuentra cualquiera de estos umbrales orientativos:

- Al menos 20 accesos a rutas sensibles, incluyendo usos legítimos como login.
- Al menos 100 peticiones observadas con 50% o más de respuestas 4xx.
- Al menos 20 peticiones observadas con 10% o más de respuestas 5xx.
- Al menos 300 peticiones observadas en un minuto.

No confirma ataques ni calcula una probabilidad. Un bot legítimo puede tener mucho tráfico; 4xx/5xx pueden tener causas normales o fallos de la aplicación. Los límites de lectura pueden ocultar picos. Los minutos repetidos por cambio horario se distinguen por offset. Al consultar un dominio, añade las diez IP con más peticiones y las rutas sensibles más consultadas. Conserva como máximo 2000 IP y agrupa las restantes; no hace resolución DNS ni confía en cabeceras X-Forwarded-For. Una dirección registrada puede pertenecer a CDN/proxy. **No bloquees una IP solo por este informe.**

## Límites operativos

- Solo abre logs con lectura. No escribe cachés, bases de datos ni archivos de resultados. Para guardar una salida puedes redirigirla tú a un archivo privado.
- No instala paquetes, crea cron, cambia Plesk/PHP, permisos, firewall, servicios ni bases de datos de las webs.
- Sin subprocess, shell, peticiones HTTP ni análisis simultáneo de dominios. No ejecutes varias copias a la vez: esta versión no impide ejecuciones simultáneas independientes.
- Prioridad CPU nice 19 y límite de espacio de direcciones virtual de 128 MiB para el propio proceso. Este límite no equivale a una promesa de RAM RSS exacta. Un proceso puede terminar sin informe si agota memoria.
- Cancela antes de leer si la carga media de un minuto supera 1 por CPU lógica o quedan menos de 256 MiB de `MemAvailable`. Lo comprueba también cada 250 fragmentos de línea. Son guardas orientativas del host, no métricas por dominio ni garantías de impacto cero; pueden no reflejar límites de contenedores/cgroups.
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

El test crea únicamente archivos temporales propios y los elimina al finalizar. No necesita leer los logs del servidor. Para una primera lectura real acotada, empieza con un solo dominio y `--seconds 2 --max-mib 1`.

Referencias de formatos y funciones: [logs de Plesk](https://support.plesk.com/hc/en-us/articles/12377744787991-Plesk-for-Linux-services-logs-and-configuration-files), [límites de recursos de Python](https://docs.python.org/3/library/resource.html), [lectura gzip](https://docs.python.org/3/library/gzip.html), [eventos de acciones de Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/fail2ban/server/actions.py).
