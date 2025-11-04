# RETO3_DESARROLLO
🧭 Contexto general 

El reto proviene del proceso “Enpresakin Harremanak” de Maristak (MKDEH), que participa en el programa Kit Consulting de Red.es, una iniciativa del Gobierno destinada a ayudar a las PYMES en su transformación digital. 

Vuestra función será actuar como asesores digitales especializados en ciberseguridad. 

 

🎯 Objetivo principal 

Diseñar e implementar soluciones de ciberseguridad para PYMES asociadas a Maristak. 
 El proyecto se divide en dos grandes partes: 

 

🧩 1. Desarrollo de una aplicación web segura 

Finalidad: 

Gestionar tarjetas monedero (de crédito y débito) que las empresas colaboradoras usan para realizar pagos relacionados con proyectos, formación, etc. 

Requisitos clave: 

🔐 Seguridad e identidad 

Implementar un sistema de autenticación y autorización centralizado. 

Integrar un mecanismo de Single Sign-On (SSO) basado en Directorio Activo o LDAP. 

Garantizar altos niveles de seguridad en la gestión de identidades e inicios de sesión. 

💳 Gestión de tarjetas 

Cada empresa tiene 2 tarjetas (crédito y débito). 

No pueden estar activas a la vez. 

Las reglas de uso son: 

Pagos hasta 500 € → activar débito. 

Pagos desde 500 € → activar crédito. 

La empresa puede activar o desactivar tarjetas desde la aplicación. 

🌐 Integración bancaria 

La aplicación debe conectarse con los Web Services del banco para ejecutar operaciones de activación/desactivación y pagos. 

Es obligatorio seguir las especificaciones técnicas y de seguridad que el banco proporciona. 

🛡️ Cumplimiento normativo y validación 

Aplicar normas de seguridad vigentes y recomendaciones OWASP (top 10). 

Elaborar un informe de seguridad que detalle las medidas implementadas y las pruebas realizadas. 

Debe existir evidencia de validación de la seguridad (tests o auditorías). 

💡 2. Desarrollo de un producto propio de ciberseguridad 

Finalidad: 

Crear una herramienta sencilla que ayude a las PYMES a analizar la seguridad de su red interna. 

Detalles técnicos: 

Se instalará en una Raspberry Pi. 

Al conectarse a la red de la empresa, ejecutará: 

🔍 Escaneo de puertos y servicios vulnerables. 

🧩 Escaneo de vulnerabilidades. 

Los resultados del análisis deben poder verse desde la aplicación web del punto 1. 
