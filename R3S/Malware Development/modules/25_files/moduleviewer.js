function toggleIde(){
    var terminal = document.getElementById("ide");
    var objectives = document.getElementById("objectives");

    // Toggle progress
    $("#progress-container").addClass("hidden");
    $("#progressToggle").removeClass("bg-gray-600");

    // If both objectives & IDE are hidden
    if(terminal.classList.contains('hidden') && objectives.classList.contains('hidden')){
        $("#ide").removeClass("hidden");
        $("#ide").removeClass("h-1/2");
        $("#ide").addClass("h-full");
        $("#description-container").removeClass("w-full");
        $("#description-container").addClass("w-full");
        $("#accessory-container").removeClass("hidden");
        $("#terminalToggle").addClass("bg-gray-600");
    } // Else if only IDE is active, then deactivate it
    else if(terminal.classList.contains('hidden') === false && objectives.classList.contains('hidden')){
        $("#ide").addClass("hidden");
        $("#ide").removeClass("h-full");
        $("#ide").addClass("h-1/2");
        $("#description-container").removeClass("w-3/4");
        $("#description-container").addClass("w-full");
        $("#accessory-container").addClass("hidden");
        $("#terminalToggle").removeClass("bg-gray-600");
    } // Else if objectives is only active, splt it 1/4 - 3/4
    else if(objectives.classList.contains('hidden') === false && terminal.classList.contains('hidden')){
        $("#objectives").removeClass("h-full");
        $("#objectives").addClass("h-1/2");
        $("#ide").removeClass("hidden");
        $("#ide").removeClass("h-full");
        $("#ide").addClass("h-1/2");
        $("#terminalToggle").addClass("bg-gray-600");
    } // Else if both are active, make objectives full (hide IDE)
    else if(objectives.classList.contains('hidden') === false && terminal.classList.contains('hidden') === false){
        $("#ide").addClass("hidden");
        $("#objectives").removeClass("h-1/2");
        $("#objectives").addClass("h-full");
        $("#terminalToggle").removeClass("bg-gray-600");
    }

}

function toggleObjectives(){
    var terminal = document.getElementById("ide");
    var objectives = document.getElementById("objectives");

    // Toggle progress
    $("#progress-container").addClass("hidden");
    $("#progressToggle").removeClass("bg-gray-600");

    // If both objectives & IDE are hidden
    if(terminal.classList.contains('hidden') && objectives.classList.contains('hidden')){
        $("#objectives").removeClass("hidden");
        $("#objectives").removeClass("h-1/2");
        $("#objectives").addClass("h-full");
        $("#description-container").removeClass("w-full");
        $("#description-container").addClass("w-full");
        $("#accessory-container").removeClass("hidden");
        $("#objectivesToggle").addClass("bg-gray-600");
    } // Else if only objectives is active, then deactivate it
    else if(terminal.classList.contains('hidden') && objectives.classList.contains('hidden') === false){
        $("#objectives").addClass("hidden");
        $("#objectives").removeClass("h-full");
        $("#objectives").addClass("h-1/2");
        $("#description-container").removeClass("w-3/4");
        $("#description-container").addClass("w-full");
        $("#accessory-container").addClass("hidden");
        $("#objectivesToggle").removeClass("bg-gray-600");
    } // Else if IDE is only active, splt in 1/4 - 3/4
    else if(terminal.classList.contains('hidden') === false && objectives.classList.contains('hidden') === true){
        $("#ide").removeClass("h-full");
        $("#ide").addClass("h-1/2");
        $("#objectives").removeClass("hidden");
        $("#objectives").removeClass("h-full");
        $("#objectives").addClass("h-1/2");
        $("#objectivesToggle").addClass("bg-gray-600");
    } // Else if both are active, make IDE full
    else if(objectives.classList.contains('hidden') === false && terminal.classList.contains('hidden') === false){
        $("#objectives").addClass("hidden");
        $("#ide").removeClass("h-1/2");
        $("#ide").addClass("h-full");
        $("#objectivesToggle").removeClass("bg-gray-600");
    }
}

function toggleScreenWidth(){
    var navbar = document.getElementById("navbar");
    if(navbar.classList.contains('hidden')){ // If full screen mode is activated
        $("#navbar").removeClass("hidden");
        $("#footer").removeClass("hidden");
        $("#height-container").removeClass("h-full");
        $("#height-container").addClass("max-h-[800px]");
        $("#description-container").addClass("overflow-auto");
        $("#enlargeToggle").addClass("bg-gray-600");
    } else{
        $("#navbar").addClass("hidden");
        $("#footer").addClass("hidden");
        $("#height-container").removeClass("max-h-[800px]");
        $("#height-container").addClass("h-full");
        $("#description-container").removeClass("overflow-auto");
        $("#enlargeToggle").removeClass("bg-gray-600");
        
    }
}

function toggleProgress(){
    var terminal = document.getElementById("ide");
    var objectives = document.getElementById("objectives");
    if(!terminal.classList.contains('hidden')){
        toggleIde();
    }
    if(!objectives.classList.contains('hidden')){
        toggleObjectives();
    }

    var progressContainer = document.getElementById('progress-container');
    if(progressContainer.classList.contains('hidden')){
    $("#ide").addClass("hidden");
    $("#objectives").addClass("hidden");
    $("#progress-container").removeClass("hidden");
    $("#progressToggle").addClass("bg-gray-600");
    let currentUrl = new URL(window.location.href);
    currentUrl.searchParams.set('progress', 'true');
    window.history.pushState({}, '', currentUrl);
    } else {
        $("#progress-container").addClass("hidden");
        $("#progressToggle").removeClass("bg-gray-600");
        let currentUrl = new URL(window.location.href);
        currentUrl.searchParams.delete('progress');
        window.history.pushState({}, '', currentUrl.toString());
      }
}
