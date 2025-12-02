console.log("button.js loaded.");

function renderAlertButton() {
  console.log("Starting to render the button...");

  const btn = document.createElement("button");
  btn.textContent = "Click Me";
  console.log("Button element created.");

  btn.addEventListener("click", () => {
    console.log("Button was clicked. Preparing alert...");
    alert("Button clicked!");
  });

  document.body.appendChild(btn);
  console.log("Button appended to the page.");
}

document.addEventListener("DOMContentLoaded", () => {
  console.log("DOM fully loaded. Rendering button...");
  renderAlertButton();
});


console.log('Full Report:test');
