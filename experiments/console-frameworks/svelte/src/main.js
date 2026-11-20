// The stylesheet is the shared one, unchanged; the components add no styles of their own.
import "../../shared/console.css";
import { mount } from "svelte";
import App from "./App.svelte";

mount(App, { target: document.body });
