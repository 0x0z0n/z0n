function toggleDropdown() {
    var difficulty = document.querySelector(".difficulty-dropdown");
    var view = document.querySelector(".view-dropdown");
    difficulty.classList.toggle("hidden");
    view.classList.add("hidden");
}

function toggleView(){
    var view = document.querySelector(".view-dropdown");
    var difficulty = document.querySelector(".difficulty-dropdown");
    view.classList.toggle("hidden");
    difficulty.classList.add("hidden");
}
