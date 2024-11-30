
//      const container = document.getElementById("container");
//      const overlayBtn = document.getElementById("overlayBtn");
//
//      overlayBtn.addEventListener("click", () => {
//        container.classList.toggle("right__panel__active");
//
//        overlayBtn.classList.remove("scale__btn-animation");
//        window.requestAnimationFrame(() => {
//          overlayBtn.classList.add("scale__btn-animation");
//        });
//      });

// Toggle forms
document.getElementById('overlayBtn').addEventListener('click', () => {
  document.getElementById('container').classList.toggle('right__panel__active');
});

