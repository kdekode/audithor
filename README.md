# Audithor 0.9.1

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
python3 -B -m unittest -q test_audithor.py
```

Hay pruebas locales de fechas, selección de logs, límites, tablas, informes y Fail2Ban. Algunas comprobaciones de permisos y enlaces necesitan Linux. Esto no sustituye comprobar los resultados con los logs de tu servidor.
