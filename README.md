# Audithor 0.10.0

Creado por **steev anderson**.

Para echar un vistazo al tráfico de las webs de un servidor Linux con Plesk, sin abrir los logs uno por uno. Ayuda a encontrar errores, URLs con mucho movimiento y cosas que merezca la pena revisar.

Necesita **Python 3.9 o superior**, sin librerías externas. Lee los archivos que ya existen: no visita las webs, no bloquea IP ni cambia servicios o configuraciones.

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

## Qué significa cada cosa

| Columna | Qué estás viendo |
|---|---|
| PETICIONES | Solicitudes leídas para la fecha elegida. Una imagen o un CSS también cuenta; no son visitantes. |
| MiB | Contenido enviado según el log. No es consumo de RAM ni CPU. |
| BOTS / HUM. / DESC. | Bot, humano probable y desconocido. Son estimaciones. |
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

También lee **Fail2Ban** desde `/var/log/fail2ban.log`. Cuenta eventos `Ban` y cruza sus IP con las vistas en esa web durante el período. La coincidencia no demuestra que esa web causara el bloqueo ni que la IP siga bloqueada ahora. No se conecta al servicio.

Elige archivos por fechas de extractos: `.1.gz` no tiene por qué ser ayer. Muestra los archivos seleccionados, los MiB leídos y las fechas encontradas. Puedes cambiar la ruta con `--fail2ban-log /ruta/al/log` u omitirlo con `--no-fail2ban`.

La tabla global normal no lee Fail2Ban ni los mensajes internos de errores. RAM y CPU históricas por dominio tampoco aparecen: estos logs no permiten reconstruirlas.

## Consumo y tiempo

Por defecto lee una **muestra de hasta 5 segundos y 8 MiB por dominio**. Con `--week` mantiene ese presupuesto, no lo multiplica por siete. Los números pueden cubrir solo parte del día o de la semana.

Lee poco a poco, sin análisis en paralelo ni cargar archivos enteros en RAM. Reduce el ritmo con carga alta y aplaza el trabajo si quedan menos de 256 MiB disponibles. El proceso tiene un límite de memoria virtual de 128 MiB; no significa que reserve o use toda esa cantidad.

Para ir más despacio, añade `--gentle`. Evita ejecutar varias copias a la vez. Los límites son cooperativos: el disco puede tardar más en responder y el impacto en producción no es cero.

El detalle añade hasta 2 segundos/2 MiB para errores internos y hasta 3 segundos/2 MiB para Fail2Ban. Este último se lee una sola vez por ejecución.

Para ampliar una lectura concreta:

```bash
python3 -I -B audithor.py ejemplo.com --yesterday --seconds 20 --max-mib 32
```

Existe `--full` para recorrer los archivos disponibles de la capa elegida. **Puede tardar mucho y quedarse en pausa si el servidor tiene carga alta.** En ese modo los límites son por tanda, no por dominio; Fail2Ban conserva su límite de 3 segundos/2 MiB.

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

Para 0.10.0: 73 pruebas, 71 correctas y 2 omitidas porque requieren Linux. Se comprueban también umbrales, ausencia de datos, correlación por fecha/zona, límites de memoria y diagnóstico con cobertura parcial.

Comparación local con 0.9.1 sobre 12.000 accesos: ambas versiones leyeron 1.396.357 bytes y encontraron las mismas peticiones. Mediana de tres recorridos: 0,4844 s CPU antes y 0,5156 s después; pico de asignaciones Python de 453,8 a 466,3 KiB. Se adaptó el lector a Windows y se simularon las pausas/comprobaciones del host. No mide RSS ni representa una prueba de carga en producción. Los presupuestos de lectura y reguladores siguen iguales.

Referencias para interpretar las métricas: [PSI en Linux](https://docs.kernel.org/accounting/psi.html), [tiempos del log de nginx](https://nginx.org/en/docs/http/ngx_http_log_module.html), [estado de PHP-FPM](https://www.php.net/manual/en/fpm.status.php) y [errores 5xx en Cloudflare](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/).
