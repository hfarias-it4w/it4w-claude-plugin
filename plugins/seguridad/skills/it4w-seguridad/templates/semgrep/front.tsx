/* eslint-disable */
// Casos de prueba de las reglas de front.yml (se corren con: semgrep --test security/semgrep).
// "ruleid:" = la regla DEBE marcar la línea siguiente; "ok:" = NO debe marcarla; "todoruleid:" = limitación conocida.
// Las variables se declaran sin valor (declare) porque Semgrep propaga constantes y un valor fijo cambiaría el resultado.
// Este archivo no debe formar parte del build ni del escaneo (el pipeline escanea solo el código fuente).
declare const html: string;
declare const otro: string;
declare const userHtml: string;
declare const nombre: string;
declare const codigo: string;
declare const texto: string;
declare const t: string;
const el = document.body;
const ACCESS_TOKEN_KEY = 'access_token';
const CLAVE = 'x';
const TOKEN_KEY = 'token';

// ruleid: react-dangerously-set-inner-html-sin-sanitizar
const a = <div dangerouslySetInnerHTML={{ __html: html }} />;

// ruleid: react-dangerously-set-inner-html-sin-sanitizar
const b = <section className="x" dangerouslySetInnerHTML={{ __html: otro }}></section>;

// ok: react-dangerously-set-inner-html-sin-sanitizar
const c = <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;

// ok: react-dangerously-set-inner-html-sin-sanitizar
const d = <p>{html}</p>;

// ruleid: js-asignacion-innerhtml
el.innerHTML = userHtml;
// ruleid: js-asignacion-innerhtml
el.outerHTML = userHtml;
// ruleid: js-asignacion-innerhtml
el.innerHTML = `<b>${nombre}</b>`;
// ok: js-asignacion-innerhtml
el.innerHTML = DOMPurify.sanitize(userHtml);
// ok: js-asignacion-innerhtml
el.innerHTML = "";
// ok: js-asignacion-innerhtml
el.innerHTML = '';
// ok: js-asignacion-innerhtml
el.innerHTML = ``;

// ruleid: js-eval-o-new-function
eval(codigo);
// ruleid: js-eval-o-new-function
const f = new Function('a', 'return a');
// ok: js-eval-o-new-function
const g = JSON.parse(texto);

// ruleid: js-token-en-storage
localStorage.setItem("access_token", t);
// ruleid: js-token-en-storage
sessionStorage.setItem("jwt", t);
// ruleid: js-token-en-storage
localStorage.setItem(TOKEN_KEY, t);
// ruleid: js-token-en-storage
localStorage.setItem(ACCESS_TOKEN_KEY, t);
// ruleid: js-token-en-storage
localStorage['token'] = t;
// ruleid: js-token-en-storage
localStorage[ACCESS_TOKEN_KEY] = t;
// ruleid: js-token-en-storage
localStorage.token = t;
// ruleid: js-token-en-storage
window.localStorage.setItem("token", t);
// todoruleid: js-token-en-storage
localStorage.setItem(CLAVE, t);
// ok: js-token-en-storage
localStorage.setItem("tema", "oscuro");
// ok: js-token-en-storage
localStorage["idioma"] = "es";
