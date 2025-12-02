# Informe de Madurez: Detección de Librerías JavaScript en xxss

Este informe analiza el estado actual, fortalezas, debilidades y recomendaciones para el módulo de detección de librerías y frameworks JavaScript en `xxss`.

## 1. Estado Actual

La detección de librerías JavaScript se realiza mediante el paquete `pkg/scanner/technologies`, orquestado por `pkg/scanner/scanner.go`.

*   **Enfoque:** Análisis estático de respuestas HTTP y scripts externos.
*   **Mecanismo:**
    *   **Firmas (Signatures):** Archivo JSON (`signatures.json`) con patrones de detección.
    *   **Patrones de Archivo:** Regex sobre URLs de scripts (ej. `jquery-3.6.0.min.js`).
    *   **Patrones de Contenido:** Regex sobre el código fuente (ej. `jQuery v3.6.0`, `React.createElement`).
    *   **Extracción de Versiones:** Captura de versiones mediante grupos en expresiones regulares.
*   **Alcance Actual:** Detecta principalmente frameworks populares como React, Vue, jQuery, Angular, etc.

## 2. Fortalezas

*   **Detección Híbrida:** La combinación de análisis de nombres de archivo (útil para CDNs) y patrones de contenido (útil para bundles minificados) aumenta la tasa de éxito.
*   **Concurrencia:** La descarga y análisis paralelo de scripts externos permite escanear múltiples dependencias sin bloquear el escáner principal.
*   **Extensibilidad:** Añadir nuevas librerías es trivial mediante la edición de `signatures.json`, sin necesidad de recompilar para cambios de firmas.
*   **Modularidad:** La arquitectura permite integrar fácilmente nuevos métodos de detección específicos para JS en el futuro.

## 3. Debilidades y Limitaciones

### 3.1. Limitaciones del Análisis Estático
*   **Inicialización Dinámica:** Muchas librerías modernas (SPAs) no dejan rastros claros en el HTML estático y solo se manifiestan en el DOM tras la ejecución (ej. exponiendo `window.React` o `window.jQuery`). El análisis actual no detecta esto.
*   **Bundlers y Minificación Agresiva:** Herramientas como Webpack o Vite pueden ofuscar nombres de variables y comentarios de versión, haciendo que las regex de contenido fallen si no hay patrones muy distintivos.
*   **Falsos Positivos:** Las expresiones regulares simples pueden coincidir con comentarios, cadenas de texto o código muerto que no representa una librería activa.

### 3.2. Precisión en Versiones
*   **Dependencia de Comentarios:** La extracción de versiones depende fuertemente de que los desarrolladores mantengan los comentarios de licencia/versión en los archivos minificados.
*   **Fragilidad de Regex:** Un cambio menor en el formato del string de versión de una librería puede romper la extracción.

### 3.3. Ausencia de Verificación de Integridad
*   **Sin Detección por Hash:** No se utiliza una base de datos de hashes (MD5/SHA) de librerías conocidas (CDNjs, unpkg). Esto impide identificar con certeza versiones específicas de archivos estándar que no han sido modificados.

## 4. Recomendaciones (Roadmap JS)

### Fase 1: Mejora de Firmas y Precisión (Corto Plazo)
1.  **Refinar Regex de Contenido:** Revisar `signatures.json` para asegurar que los patrones de contenido sean únicos y robustos frente a minificación.
2.  **Ampliar Base de Datos:** Añadir firmas para un espectro más amplio de librerías de utilidad (Lodash, Moment.js, Axios) y frameworks UI (Tailwind - si se detecta en JS, Material UI).
3.  **Validación de Contexto:** Implementar lógica para verificar si un match ocurre dentro de un string o comentario, reduciendo falsos positivos.

### Fase 2: Identificación Avanzada (Medio Plazo)
4.  **HashDetector:** Implementar un detector que calcule el hash de los scripts descargados y lo compare con una base de datos local de hashes de librerías populares (CDN). Esto garantiza una identificación de versión 100% precisa para archivos stock.
5.  **Análisis de Mapas de Fuentes (Source Maps):** Si se detectan archivos `.map`, intentar leerlos para descubrir las librerías originales que componen un bundle.

### Fase 3: Detección Dinámica (Largo Plazo)
6.  **Ejecución en Sandbox/Headless:** Integrar un motor ligero (o headless browser) para ejecutar la página y verificar la existencia de objetos globales (`window.React`, `window.$`, `window.Angular`). Esta es la forma definitiva de detección pero añade complejidad significativa.

## 5. Conclusión

El módulo actual es una base sólida para la detección estática de librerías JavaScript, destacando por su concurrencia y facilidad de configuración. Sin embargo, para alcanzar un nivel de madurez alto en el ecosistema JS moderno, es crucial evolucionar hacia técnicas que no dependan solo de regex, incorporando **detección por hash** y, eventualmente, **análisis dinámico** para superar las barreras de los bundlers modernos.
