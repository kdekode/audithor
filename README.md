# Audithor 0.8.4

Creado por **steev anderson**. Inspección local de logs Linux/Plesk, en consola y sin dependencias de Python externas. Requiere Python 3.9+ y zonas horarias del sistema. No usa idxo-security ni su instalador.

## Cambio principal: vista rápida predeterminada

Las versiones anteriores recorrían todas las rotaciones y dormían 10 ms por línea en modo suave: 100 000 líneas podían necesitar más de 16 minutos solo por esas pausas. Además esperaban indefinidamente si la carga media superaba el umbral. Esta versión:

- Elimina por completo el correo, `--send` y la ejecución de comandos externos.
- Usa por defecto una **muestra de hasta 5 segundos y 8 MiB descomprimidos por dominio** para accesos.
- Selecciona archivos compatibles por familia HTTP/HTTPS, en lugar de toda la retención.
- Para hoy, lee una cola reciente del log activo cuando no cabe en el presupuesto.
- Comprueba fechas de extractos antes de elegir: prefiere archivos sin comprimir (`.processed` o activos) cuyo intervalo observado sea compatible con el día. No supone que `.1.gz` sea ayer: la rotación puede ser por tamaño y contener meses. Si no hay texto compatible, examina inicios gzip y prefiere la fecha inicial más reciente anterior o igual al día. Si no puede confirmar un candidato, conserva una selección provisional y avisa. Siempre filtra cada línea por su fecha real.
- Reparte el tiempo/bytes restantes entre HTTP y HTTPS para que el primero no agote todo el presupuesto.
- Regula CPU y lectura por bloques de 128 líneas/fragmentos, en lugar de dormir en cada línea.
- En vista rápida, la carga alta reduce el ritmo propio; **no activa la espera indefinida**. Si no se puede comprobar el estado o quedan menos de 256 MiB disponibles, se aplaza la lectura.

La vista rápida siempre se presenta como **muestra**, nunca como total diario. Puede omitir IP, rutas, picos o errores que no estén en los archivos/fragmentos leídos. Los porcentajes y el orden del resumen describen esa muestra. Si no hay accesos de la fecha, no demuestra ausencia de tráfico. El informe muestra fuente, archivos seleccionados, fechas encontradas y avisos.

La selección de accesos dedica como máximo un segundo cooperativo, 256 KiB y un octavo de los bytes restantes a extractos de hasta 8 KiB del inicio/final en texto, o solo inicio en gzip. Ese tiempo/lectura se descuentan del presupuesto del dominio. Una coincidencia de intervalo en muestras no garantiza que todas las fechas intermedias estén presentes. Si varios archivos de texto son compatibles, puede seleccionar más de uno por familia y reparte el presupuesto entre ellos; no mezcla Apache y nginx.

Para fechas pasadas en texto sin comprimir, realiza una búsqueda aproximada hacia el día: como máximo 14 lecturas de hasta 4 KiB, contadas en su presupuesto, con un margen previo de 16 KiB. Después alinea la línea y cuenta únicamente registros del día. **Supone orden cronológico**; puede omitir registros tardíos o fuera de orden y por eso sigue siendo muestra. Si no puede encontrar fechas coherentes en las sondas, avisa y lee desde el inicio. No aplica esta búsqueda a gzip, porque descomprimir hasta una posición no sería un acceso aleatorio barato.

## Preparación y uso

Sube `audithor.py` y opcionalmente el lanzador `audithor` a una carpeta privada fuera de la raíz web, por ejemplo `/too-custom/audithor/` o la carpeta que ya utilizas. Si lo ejecutas como root, el código y su carpeta no deben ser modificables por cuentas de las webs. Usa permisos de lectura ya existentes; el programa no cambia permisos para conseguir acceso.

Desde la carpeta del script:

```sh
python3 -I -B audithor.py --yesterday
```

Sin indicar un dominio, muestra una **tabla con una fila por dominio**, disponible en cuanto termina su lectura. Columnas: DOMINIO, PETICIONES, MiB, BOTS %, HUM. %, DESC. %, 4xx (#), 5xx (#), PICO/MIN y ESTADO. HUM. significa humano probable; DESC. es desconocido, no se suma a humanos. No inventa páginas/usuarios únicos ni considera que todo lo que no parece bot sea humano.

ESTADO usa REV:n para el número de umbrales activados, M para muestra, A para avisos adicionales y SIN FECHA cuando no se observaron accesos de la fecha. Si no se activan umbrales, muestra el volumen orientativo del pico (BAJA/MODERADA/ALTA). Los nombres largos se abrevian solo en la tabla. La tabla requiere una terminal ancha, de unos 126 caracteres; el detalle por dominio conserva el nombre completo, explicaciones, archivos, fechas, rankings y avisos.

Si aparece SIN FECHA, peticiones y MiB se muestran como N/D: no se deduce tráfico cero de una muestra sin datos del día. Que existan archivos `.1.gz` no demuestra que contengan ayer. Las rotaciones pueden no ser diarias y la muestra de un archivo puede empezar en otra fecha.

Analiza **uno a uno**, imprimiendo cada fila al acabar. Solo si quedan dominios después del número **70**, espera **`start` + Enter** para los siguientes 70. Con 64 dominios muestra todos sin pedir `start`; no ejecuta 70 análisis simultáneos. Enter solo no inicia más trabajo; `q` termina y muestra el resumen de lo analizado. **No ordena antes de analizar**: el resumen final se prepara con los contadores acumulados, sin releer logs. El indicador temporal de lectura se escribe en stderr solo si es terminal, para mantener limpias las filas.

```sh
python3 -I -B audithor.py                       # muestra de hoy
python3 -I -B audithor.py ejemplo.com --yesterday
python3 -I -B audithor.py --date 2026-10-18
python3 -I -B audithor.py --yesterday --once    # como máximo los primeros 70
```

`-I` aísla Python de variables/directorios de importación no deseados; `-B` evita crear bytecode. El lanzador permite `sh /ruta/audithor` y añade esas opciones. Sin terminal interactiva, se leen como máximo 70 dominios en modo normal. Ctrl+C durante el recorrido muestra el resumen parcial de los dominios terminados; otra interrupción termina el programa. Cerrar SSH o reiniciar el proceso pierde la posición: no hay caché ni reanudación entre ejecuciones. El resumen final también pagina cada 70 filas. Los límites por dominio y la regulación de recursos no cambian.

## Ampliar solo lo necesario

Para aumentar el presupuesto sobre los archivos probables de una web:

```sh
python3 -I -B audithor.py ejemplo.com --yesterday --seconds 20 --max-mib 32
```

Para recorrer **todos los archivos seleccionados de una sola capa**:

```sh
python3 -I -B audithor.py ejemplo.com --yesterday --full
```

`--full` es optativo. Conserva la lectura continua, descansa entre tandas y espera si la carga supera 1 por CPU lógica o la memoria no permite seguir. Puede durar horas o permanecer esperando si el host no se recupera. `--seconds`/`--max-mib` son límites por tanda en este modo, no por dominio. No aumenta automáticamente el umbral para forzar lecturas. Los ficheros activos de texto se leen hasta el tamaño capturado al abrirlos; gzip rotados se presuponen estáticos. Acabar los archivos no demuestra que Plesk haya conservado todos los accesos.

`--sample` sigue aceptándose como alias de la vista rápida. Es incompatible con `--full`. Rangos: `--seconds` 1–1800; `--max-mib` 1–1024. Son límites cooperativos entre lecturas; una operación de disco bloqueada puede tardar más en responder.

Para hoy, `--gzip` permite candidatos comprimidos; las fechas anteriores los incluyen automáticamente. Elegir un gzip no lo descomprime entero en RAM: se lee progresivamente hasta el presupuesto. No se usa seek gzip para simular un acceso aleatorio barato. Para fechas antiguas o rotaciones no diarias puede hacer falta `--full`; la heurística de archivos no garantiza encontrar el día.

## Qué lee y qué significa

Lee archivos de acceso, sin visitar webs ni rastrear URLs. Raíz predeterminada: `/var/www/vhosts/system/DOMINIO/logs`; `--root` admite otra raíz con la misma estructura.

Selecciona una sola capa para evitar sumar nginx y Apache: para hoy prefiere `proxy_access_log`/`proxy_access_ssl_log`. Para fechas pasadas compara la disponibilidad de históricos; elige Apache `access_log`/`access_ssl_log` si conserva rotaciones que nginx no tiene. En igualdad prefiere nginx. Soporta `.processed`, `.N`, `.processed.N` y `.gz`. Rechaza enlaces simbólicos, dispositivos y FIFOs, y usa `openat`/`O_NOFOLLOW` en Linux. Deduplica hardlinks por inode; copias distintas de eventos repetidos o rotaciones simultáneas pueden alterar recuentos.

**No filtra únicamente errores:** necesita también accesos normales de la muestra para calcular porcentajes útiles. Para cada línea de formato combined interpreta fecha, IP, ruta sin query, código HTTP, tamaño y User-Agent. Una solicitud puede ser una página, imagen, CSS, API o bot; no equivale a una persona.

| Métrica | Significado |
|---|---|
| Peticiones | Solicitudes leídas que corresponden a la fecha elegida; en vista rápida no son todo el día. |
| Contenido enviado | Suma del tamaño de respuesta registrado, normalmente cuerpo sin cabeceras. No es RAM/CPU ni velocidad de conexión. |
| Bots/humano probable/desconocido | Heurísticas de User-Agent y rutas; el agente puede falsificarse. |
| 4xx | Rechazos o recursos no encontrados, como 403/404. `58 (2,1%)` significa 58 de todas las solicitudes leídas de la fecha. |
| 5xx | Errores del servidor, como 500/503; también muestra cero si no se observaron. |
| Pico | Mayor recuento en un minuto natural observado, no tráfico sostenido ni visitantes. Se muestra el minuto y offset. |
| Rutas sensibles | Accesos a patrones como `.env`, `.git`, login o xmlrpc; algunos son legítimos. |

Actividad orientativa por el pico: BAJA <60/min, MODERADA 60–599, ALTA 600–2999 y MUY ALTA >=3000. No está calibrada a cada web ni equivale a riesgo. Un pico aislado de 355/min (~5,9/s de media dentro del minuto) no activa alerta por sí mismo. Los picos repetidos por cambio horario se distinguen por offset.

Marca REVISAR por al menos 20 accesos sensibles con respuesta 4xx; por >=50% de 4xx sobre >=100 solicitudes; o por >=10% de 5xx sobre >=20 solicitudes. Son señales orientativas de problemas, no confirmación de ataques. El resumen prioriza número de condiciones, accesos sensibles rechazados, 5xx, 4xx y tráfico como desempate. Sin accesos de la fecha: al final, sin valoración. Errores normales de aplicación y usos legítimos pueden activar condiciones; una muestra puede ocultarlas.

RAM/CPU históricas por dominio se han retirado: los access logs no permiten reconstruirlas. El programa tampoco aplica bloqueos.

## Detalle y Fail2Ban

Al indicar un dominio o guardar HTML se calculan rankings de URLs, bytes, errores, IP y rutas sensibles. Mantiene hasta 2000 valores por ranking y agrupa los demás; muestra diez en consola y veinte en HTML. No garantiza un top exacto con cardinalidad mayor. Las IP pueden ser proxies/CDN; no hace DNS ni confía en cabeceras reenviadas.

En vista rápida, los mensajes internos de nginx/Apache/PHP tienen un presupuesto adicional de hasta **2 segundos/2 MiB**, seleccionando un archivo probable de la misma capa. Solo conserva categorías, no mensajes completos. Para un dominio o HTML lee además una muestra de Fail2Ban de hasta **3 segundos/2 MiB**, una sola vez por ejecución, sin cliente ni socket. Así un detalle puede tardar aproximadamente 5+2+3 segundos por defecto, más operaciones de disco y pausas acotadas. La vista global normal no analiza estos historiales adicionales.

Fail2Ban lee `/var/log/fail2ban.log` y una rotación probable; `--fail2ban-log` cambia la ruta y `--no-fail2ban` lo omite. Incluso con `--full`, su lectura mantiene el límite 3 s/2 MiB, aunque admite todas sus rotaciones hasta agotarlo. Conserva hasta 20 000 IP y 100 jails más un grupo de otras. Cuenta eventos `Ban`, sin `Unban`, `Restore Ban` ni `Found`; no confirma aplicación del firewall ni enumera bloqueos activos. Coincidencia por dominio significa que la IP visitó esa web y tuvo evento Ban ese día, no que la web originara el bloqueo.

Los access logs con offset se convierten a `Europe/Madrid` o `--timezone`. Los errores internos y Fail2Ban sin offset se filtran por su fecha local escrita: se presupone la zona elegida. Si no coincide con la del servidor, los cruces cerca de medianoche pueden ser imprecisos. Si Fail2Ban solo escribe en journal/syslog, muestra N/D y no cambia su configuración.

## HTML local, sin correo

```sh
python3 -I -B audithor.py --yesterday --report
python3 -I -B audithor.py ejemplo.com --yesterday --report --full
```

`--report` recorre automáticamente todos los dominios seleccionados, sin esperar `start`; la vista sigue siendo rápida salvo `--full`. Escribe un HTML con apartados por dominio, conforme termina cada uno, y resumen final. No acumula todos sus detalles en RAM ni usa motor PDF, navegador, JavaScript o recursos externos.

Guarda en `reports/` junto al script, fuera de la raíz web: directorio 700 del usuario actual, archivos exclusivos 600 con identificador aleatorio. Rechaza enlaces/carpetas no privadas y no cambia permisos existentes. Límite 2 MiB por informe; al alcanzarlo se marca parcial. Incluye cobertura y avisos; no lo presenta como tráfico diario completo. No borra informes antiguos: elimina tú los que ya no necesites. Añade **`reports/` a `.gitignore`**; contienen IP y rutas privadas.

El correo y `--send` se han eliminado. No se instalan ni modifican servicios de correo.

## Recursos y diagnóstico

Prioridad CPU nice 19 y límite de espacio de direcciones virtual de **128 MiB** para el propio proceso. No equivale a una promesa de RSS exacta; puede terminar si agota memoria. No ejecuta procesos externos, servicios, cron, peticiones HTTP, cambios Plesk/firewall/permisos de webs ni análisis paralelos. Evita ejecutar varias copias independientes a la vez; no hay bloqueo entre procesos.

Regula por bloques usando tiempo CPU del proceso, tiempo transcurrido y bytes leídos. Objetivos aproximados: 10% de **un núcleo** y 2 MiB/s normalmente; 5% y 512 KiB/s con `--gentle`; con carga alta en vista rápida, 2% y 256 KiB/s. Son reguladores cooperativos, **no cuotas duras del kernel**: ráfagas, parseo de una línea, gzip y disco pueden desviarse. Cada descanso individual se limita a 250 ms. La prioridad de disco no se modifica; si ya tienes `ionice`, puedes anteponer `ionice -c 3`.

La carga media alta no significa que Audithor use esa RAM/CPU ni predice por sí sola una caída. La vista rápida evita bloquearse solo por ella, limita su propio trabajo y conserva la protección de memoria. Esto no garantiza impacto cero en producción, especialmente si el cuello de botella es el disco.

```sh
python3 -I -B audithor.py --diagnose
/usr/bin/time -v python3 -I -B audithor.py --yesterday --once
```

El diagnóstico no abre logs. En `time -v`, `Maximum resident set size` indica el pico RSS en KiB del proceso. No instales herramientas si faltan solo para ejecutar Audithor. Inventario limitado a 10 000 entradas/15 s, directorios de logs a 4096 entradas y fuentes a 128 archivos. Líneas de 16 KiB; excesivas o incompletas se descartan con aviso. No se leen archivos enteros en memoria.

Para investigar SIN FECHA sin recorrer todos los históricos:

```sh
python3 -I -B audithor.py ejemplo.com --yesterday --inspect-logs
```

Requiere un dominio y no genera informes ni lee Fail2Ban. Muestra ambas capas de accesos disponibles, marca los archivos que seleccionaría el análisis y obtiene fechas de extractos pequeños: inicio de hasta 16 KiB por archivo y, para texto sin comprimir, hasta 16 KiB adicionales del final. No lee el final de gzip, porque requeriría recorrerlo. Máximo 32 archivos y 3 segundos cooperativos entre archivos, más hasta un segundo/256 KiB para preselección y el inventario/metadatos. Una lectura bloqueada puede tardar más. No imprime IP, rutas, agentes ni líneas originales. COMBINED indica cuántas líneas de los extractos acepta el parser, no solicitudes del día. Una fecha encontrada en un extracto no prueba la cobertura del archivo completo. La selección del diagnóstico también puede quedar provisional si agota sus sondas.

## Verificación

Pruebas locales en Windows/Python 3.14 para selección histórica Apache/nginx, archivos rápidos HTTP/HTTPS, cola reciente, límites, fechas, parser, filtros, cardinalidad, señales, espera explícita de `--full`, continuidad gzip, tandas con `start`, filas alineadas y HTML escapado/acotado. Una regresión reproduce `.1.gz` de mayo y `.processed` con 20 000 accesos antiguos, 100 del día objetivo y 10 de hoy por familia: selecciona ambos `.processed`, recupera exactamente los 200 accesos de la fecha y permanece dentro de 256 KiB de lectura. Las pruebas de descriptores/enlaces/permisos reales requieren Linux y se omiten aquí. No se ha validado esta revisión en tu servidor.

Fixture local de 12 000 accesos (1 356 000 bytes), con lector de archivos adaptado a Windows y sin medir presión real del host: **8,289 s transcurridos y 0,812 s CPU**. Es una medida de esa prueba, no una promesa de velocidad/RAM en producción. Verifica el comportamiento de regulación sin la antigua pausa fija por línea.

```sh
python3 -B -m unittest -v test_audithor.py
python3 -I -B audithor.py --version
```

Referencias: [logs Plesk](https://support.plesk.com/hc/en-us/articles/12377744787991-Plesk-for-Linux-services-logs-and-configuration-files), [límites de recursos Python](https://docs.python.org/3/library/resource.html), [gzip](https://docs.python.org/3/library/gzip.html), [eventos Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/fail2ban/server/actions.py).
