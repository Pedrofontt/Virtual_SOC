

Ir al contenido
Cómo usar Gmail con lectores de pantalla
1 de 2,425
(sin asunto)
Recibidos

Pedro Nunez <pedrofontt28@gmail.com>
5:47 p.m. (hace 10 minutos)
para mí

SOC Virtual Lab — Especificación de brainstorming

Estado: Brainstorming / diseño preliminar
Versión: 0.1
Última actualización: 2026-10-11
Objetivo: Retomar el diseño más adelante, resolver decisiones pendientes y pulir la arquitectura antes de implementar.

1. Visión del proyecto

Construir un laboratorio SOC virtual, con software gratuito, que emule de forma controlada una pequeña infraestructura empresarial y permita demostrar un flujo funcional de detección e investigación de incidentes.

El proyecto no se considera exitoso por tener herramientas instaladas. El criterio principal es que se generen alertas reales y reproducibles a partir de actividad simulada, que puedan investigarse y, cuando corresponda, activar una respuesta automatizada.

Objetivo de portafolio

Documentar el proyecto de forma que un reclutador o profesional de seguridad pueda entender y reproducir:

● La arquitectura y la segmentación de red.

● Las fuentes de telemetría.

● Las reglas de detección y su lógica.

● Los incidentes de prueba, evidencias y resultados.

● La integración entre SIEM, endpoint, identidad y SOAR.

● Las limitaciones del laboratorio y las decisiones técnicas.

2. Alcance preliminar

Componentes deseados

|Capacidad                    |Candidato preliminar                           |Propósito                                                                                                                  |
|-----------------------------|-----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
|SIEM / monitoreo de host     |Wazuh                                          |Recibir logs, buscar eventos, correlacionar actividad y generar alertas.                                                   |
|EDR / visibilidad de endpoint|Agente Wazuh + Sysmon; evaluar Velociraptor    |Recopilar telemetría de endpoint e investigar actividad sospechosa. No se asume equivalencia completa con un EDR comercial.|
|Identidad                    |Samba AD DC; evaluar Windows Server Evaluation |Dominio, usuarios, grupos, autenticación y actividad privilegiada.                                                         |
|SOAR                         |Shuffle; alternativa: scripts Python y webhooks|Enriquecimiento, playbooks, registro de incidentes y respuesta controlada.                                                 |
|ETP (Email Threat Protection)|Proxmox Mail Gateway                           |Filtrado y análisis de correo de laboratorio; evaluar cómo generar y exportar eventos.                                     |
|Monitoreo de red / NDR       |Suricata; Zeek como posible complemento        |Detectar actividad de red en tráfico controlado y enviar eventos al SIEM.                                                  |
|Virtualización               |Por decidir según CPU, RAM y sistema anfitrión |Ejecutar los servicios de laboratorio.                                                                                     |

Nota: Los candidatos no son decisiones definitivas. Se deben validar compatibilidad, recursos, licencias, facilidad de integración y requisitos actuales antes de instalarlos.

3. Recursos disponibles y desconocidos

Datos conocidos

● Equipo: PC personal.

● Almacenamiento: 512 GB.

● RAM: pendiente de confirmar; se ha considerado el escenario de 16 GB, pero podría ser 32 GB.

● CPU: modelo, núcleos físicos y procesadores lógicos pendientes de confirmar.

● Objetivo: proyecto demostrable para portafolio.

● ETP significa Email Threat Protection.

Implicaciones preliminares

● Si hay 16 GB de RAM, ejecutar los servicios por fases y evitar encender todas las VMs simultáneamente.

● Si hay 32 GB, considerar más servicios simultáneos, sujeto al procesador y al consumo real.

● No decidir aún el hipervisor ni las asignaciones finales de recursos.

● Reservar espacio para el sistema anfitrión, discos virtuales, logs, índices, snapshots y evidencias.

● Usar retención de logs limitada al inicio y revisar el crecimiento del indexador.

4. Arquitectura conceptual preliminar

Zonas lógicas

● LAB-CORP: clientes y servidores de la empresa simulada.

● LAB-SEC: SIEM, SOAR y herramientas de investigación/seguridad.

● LAB-MGMT: acceso administrativo a consolas y dashboards.

● LAB-EDGE: servicios de correo y otros servicios de prueba expuestos de forma controlada.

La segmentación es conceptual por ahora. Se deben decidir el hipervisor, las redes virtuales, las reglas de comunicación, el DNS, el direccionamiento IP y el acceso a Internet.

Flujo de datos esperado

1. Los endpoints, el dominio, los servidores, el correo y las herramientas de red generan eventos.

2. Los agentes o integraciones envían telemetría al SIEM.

3. El SIEM ingiere y normaliza eventos, ejecuta reglas y genera alertas.

4. El analista revisa la evidencia y determina si la alerta es válida.

5. Para los casos integrados, el SIEM envía la alerta al SOAR.

6. El SOAR enriquece la alerta, crea o actualiza el incidente y ejecuta una acción segura cuando esté autorizada.

7. Se documentan el resultado, las marcas de tiempo y las métricas.

Este flujo es lógico, no una obligación de que todas las alertas pasen por todas las herramientas.

5. Distribución de VMs — borrador, no configuración final

La siguiente distribución solo sirve para visualizar órdenes de magnitud y no se debe interpretar como viable con todas las VMs encendidas en un equipo de 16 GB.

|VM / función                              |RAM orientativa                   |Disco virtual orientativo|Notas                                                                     |
|------------------------------------------|---------------------------------:|------------------------:|--------------------------------------------------------------------------|
|SOC01 — Wazuh manager, indexer y dashboard|5 GB                              |80 GB                    |Componente central; revisar requisitos según versión y volumen de eventos.|
|DC01 — Samba AD DC y DNS                  |2 GB                              |25 GB                    |Dominio de laboratorio.                                                   |
|WIN01 — Windows cliente                   |3 GB                              |60 GB                    |Agente, Sysmon y eventos de seguridad.                                    |
|SOAR01 — Shuffle                          |2 GB iniciales, por validar       |40 GB                    |Dependencias pueden requerir más memoria.                                 |
|MAIL01 — Proxmox Mail Gateway             |2 GB iniciales, por validar       |30 GB                    |Fase posterior; validar requisitos y topología de correo.                 |
|Anfitrión                                 |Al menos 2 GB, preferiblemente más|Resto                    |Sistema operativo, hipervisor y herramientas.                             |

Las asignaciones deben ajustarse a la documentación vigente de cada herramienta. En el escenario de 16 GB, comenzar con Wazuh + un endpoint y añadir identidad después es más realista. Las herramientas de red o correo pueden ejecutarse en fases posteriores o reemplazarse temporalmente por fuentes de eventos más ligeras.

6. Criterio de éxito y definición de “funcional”

El criterio central es demostrar alertas útiles, no solo que los dashboards carguen.

Criterios mínimos de aceptación

- Una fuente de eventos real o reproducible está conectada al SIEM.

- Se ejecuta una actividad de prueba documentada y autorizada dentro del laboratorio.

- La actividad produce los eventos esperados en la fuente.

- Los eventos llegan al SIEM con campos útiles y marcas de tiempo.

- Una regla genera la alerta esperada de forma reproducible.

- La alerta incluye evidencia suficiente para investigarla.

- Se documenta el resultado esperado y el observado.

- Se comprueba que una actividad benigna similar no genere alertas innecesarias, cuando sea pertinente.

- El caso de uso se puede repetir siguiendo la documentación del repositorio.

Nivel de éxito por etapas

Nivel 1 — Detección funcional

● Un endpoint envía telemetría.

● Al menos 3 casos de uso producen alertas reproducibles.

● Las alertas se pueden investigar desde el SIEM.

Nivel 2 — Entorno empresarial emulado

● Hay dominio, cuentas y equipos unidos al dominio.

● Se correlacionan eventos de al menos dos fuentes, por ejemplo endpoint + autenticación.

● Se documentan casos de uso, evidencias y falsos positivos.

Nivel 3 — SOC integrado

● El SIEM activa un flujo SOAR.

● El playbook enriquece y registra el incidente.

● Una respuesta controlada se demuestra en un activo de prueba, con salvaguardas y registro de auditoría.

● Se reportan MTTD y, cuando corresponda, MTTR de los ejercicios.

Nivel 4 — Extensiones

● Eventos de correo y/o tráfico de red integrados.

● Más reglas, dashboards, investigación avanzada y pruebas de regresión.

● Retención, capacidad, backups y recuperación documentados.

7. Casos de uso candidatos

Los escenarios deben ejecutarse solo en el laboratorio aislado y con cuentas/activos de prueba.

|Caso de uso                                       |Fuente principal                |Resultado esperado                                          |
|--------------------------------------------------|--------------------------------|------------------------------------------------------------|
|Múltiples autenticaciones fallidas                |Eventos Windows / dominio       |Alerta por umbral de fallos en un periodo definido.         |
|Inicio de sesión exitoso tras fallos              |Eventos de autenticación        |Correlación de secuencia sospechosa.                        |
|Creación de usuario o cambio de grupo privilegiado|Eventos del dominio             |Alerta de cambio de identidad relevante.                    |
|Actividad de PowerShell sospechosa simulada       |Sysmon / logs de PowerShell     |Alerta basada en evento o patrón de prueba documentado.     |
|Modificación de archivo monitorizado              |FIM de Wazuh                    |Alerta de integridad.                                       |
|Indicador de red de prueba                        |Suricata u otra fuente          |Alerta de red visible en el SIEM.                           |
|Correo de phishing simulado                       |Logs del ETP / mensaje de prueba|Evento de análisis o filtrado, si la integración lo permite.|
|Automatización de incidente                       |SIEM → SOAR                     |Enriquecimiento, creación de incidente y acción controlada. |

Cada caso de uso deberá definir: hipótesis, prerequisitos, pasos de prueba, eventos esperados, regla, severidad, evidencia, resultado esperado, falsos positivos conocidos y procedimiento de limpieza.

8. Seguridad del laboratorio

● Mantener el laboratorio aislado de la red doméstica y de sistemas de producción.

● No exponer servicios deliberadamente vulnerables a Internet.

● Usar cuentas y contraseñas de laboratorio únicas; no reutilizar credenciales reales.

● No usar malware real como requisito para validar detecciones; preferir simulaciones benignas y técnicas controladas.

● Limitar las acciones de respuesta automática a activos de prueba.

● Requerir aprobación humana para acciones destructivas o de alto impacto.

● No almacenar secretos, tokens ni datos personales en el repositorio.

● Mantener registro de las acciones del SOAR y un mecanismo de recuperación de la VM.

9. Limitaciones conocidas

● El hardware puede impedir ejecutar simultáneamente todas las herramientas.

● Las ediciones gratuitas no necesariamente incluyen todas las funciones comerciales.

● Samba AD no replica todas las funciones específicas de Microsoft Active Directory en Windows Server.

● Wazuh más Sysmon proporciona buena telemetría y detección de host, pero no debe describirse automáticamente como equivalente a un EDR empresarial completo.

● Proxmox Mail Gateway no implica paridad con una suite comercial avanzada de protección de correo.

● El volumen de logs e índices puede agotar el almacenamiento si no se configura la retención.

● Las capacidades concretas y sus requisitos deben confirmarse con documentación oficial vigente antes de la implementación.

10. Estimación preliminar de esfuerzo

Estimación de planificación para una persona que trabaja de forma constante algunas horas por semana y que aprende o investiga mientras construye el proyecto. No es una garantía.

|Hito                                                          |Tiempo orientativo                                     |
|--------------------------------------------------------------|-------------------------------------------------------|
|Diseño, selección de herramientas y decisiones de arquitectura|2–5 días                                               |
|Hipervisor, redes virtuales y VM base                         |2–5 días                                               |
|Wazuh y primer endpoint con eventos                           |3–7 días                                               |
|Primeros 3 casos de uso de detección reproducibles            |3–7 días                                               |
|Dominio, cuentas y correlación de identidad                   |3–7 días                                               |
|Integración SOAR y primer playbook                            |4–10 días                                              |
|Correo o monitoreo de red como extensión                      |4–10 días adicionales por integración, según obstáculos|
|Pruebas, afinación, documentación y material de portafolio    |4–8 días                                               |

Estimación global orientativa:

● Prueba de concepto con alertas funcionales: aproximadamente 2–4 semanas.

● Portafolio sólido con dominio, varios casos de uso y una automatización: aproximadamente 4–8 semanas.

● Laboratorio más completo con SIEM, identidad, SOAR, correo, red, pruebas y documentación pulida: aproximadamente 8–12 semanas o más.

Los tiempos suponen dedicación regular; el calendario se alarga si se trabaja solo los fines de semana o si hay problemas de rendimiento, compatibilidad o integración. Conviene medir el progreso por hitos funcionales, no por fechas rígidas.

11. Decisiones pendientes para la siguiente sesión

- Confirmar CPU exacta, núcleos físicos, procesadores lógicos y RAM.

- Confirmar sistema operativo anfitrión y espacio libre real en disco.

- Elegir hipervisor.

- Elegir Samba AD o Windows Server Evaluation para el dominio.

- Decidir si Shuffle se ejecuta en VM propia, se pospone o se reemplaza inicialmente por scripts.

- Definir el primer caso de uso y su prueba de aceptación.

- Diseñar subredes, direccionamiento, DNS, rutas y reglas de aislamiento.

- Establecer retención inicial de logs.

- Verificar versiones, licencias y requisitos actuales de cada herramienta.

- Acordar qué funciones deben estar encendidas simultáneamente y cuáles pueden ejecutarse por fases.

12. Regla de trabajo para retomar el brainstorming

Antes de instalar herramientas, continuar afinando el documento y resolver las decisiones pendientes. Para cada componente, evaluar:

1. Qué capacidad necesitamos demostrar.

2. Qué herramienta gratuita la proporciona.

3. Qué datos recibe y emite.

4. Qué recursos consume.

5. Cómo se integra con el resto.

6. Cómo probaremos que funciona.

7. Qué limitaciones y alternativas tiene.

No iniciar la implementación hasta que la arquitectura mínima, los recursos reales y el primer criterio de aceptación estén acordados.



✕Merlin