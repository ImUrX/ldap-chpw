window.onload = () => {
    const search = window.location.search instanceof URLSearchParams 
        ? window.location.search : new URLSearchParams(window.location.search);
    if(search.has("error")) {
        const error = search.get("error");
        const element = document.querySelector(".error");
        element.querySelector("div").textContent = error;
        element.style.display = "block";
    } else if(search.has("info")) {
        const info = search.get("info");
        const element = document.querySelector(".error");
        element.querySelector("div").textContent = info;
        element.classList.replace("error", "info");
        element.style.display = "block";
    }
};