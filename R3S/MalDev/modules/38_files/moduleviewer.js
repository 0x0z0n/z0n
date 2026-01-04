function syncMaldevParam() {
  // Single source of truth: clear all known pane params, then set the one that's visible
  const u = new URL(window.location.href);
  ['maldevdb','progress','toc','objectives'].forEach(k => u.searchParams.delete(k));

  if (!$("#maldevDB").hasClass("hidden")) {
    u.searchParams.set("maldevdb","true");
  } else if (!$("#progress-container").hasClass("hidden")) {
    u.searchParams.set("progress","true");
  } else if (!$("#toc-container").hasClass("hidden")) {
    u.searchParams.set("toc","true");
  } else if (!$("#objectives").hasClass("hidden")) {
    u.searchParams.set("objectives","true");
  }

  window.history.replaceState({},'',u);
}

function resetPanels(){
  // hide all side panels & accessory wrapper
  $("#accessory-container,#maldevDB,#objectives,#progress-container,#toc-container").addClass("hidden");
  // clear all toggle button highlights
  $("#terminalToggle,#objectivesToggle,#progressToggle,#tocToggle").removeClass("bg-gray-600");
  // remove all pane params (sync will add the correct one later)
  syncMaldevParam();
}

function toggleIde(){
  const hidden = $("#maldevDB").hasClass("hidden");
  resetPanels();

  // Prepare URL
  let u = new URL(window.location.href);
  ['progress','toc','objectives'].forEach(k => u.searchParams.delete(k));

  if (hidden){
    $("#accessory-container,#maldevDB").removeClass("hidden");
    $("#terminalToggle").addClass("bg-gray-600");
    u.searchParams.set("maldevdb","true");
  } else {
    $("#accessory-container").addClass("hidden");
    u.searchParams.delete("maldevdb");
  }

  window.history.pushState({},'',u);
  syncMaldevParam();
}

function toggleObjectives(){
  const hidden = $("#objectives").hasClass("hidden");
  resetPanels();

  let u = new URL(window.location.href);
  ['progress','toc','maldevdb'].forEach(k => u.searchParams.delete(k));

  if (hidden){
    $("#accessory-container,#objectives").removeClass("hidden");
    $("#objectivesToggle").addClass("bg-gray-600");
    u.searchParams.set("objectives","true");   // ✅ add &objectives=true
  } else {
    $("#accessory-container").addClass("hidden");
    u.searchParams.delete("objectives");
  }

  window.history.pushState({}, '', u);
  syncMaldevParam();
}

function toggleToC(){
  const hidden = $("#toc-container").hasClass("hidden");
  resetPanels();

  let u = new URL(window.location.href);
  ['progress','maldevdb','objectives'].forEach(k => u.searchParams.delete(k));

  if (hidden){
    $("#accessory-container,#toc-container").removeClass("hidden");
    $("#tocToggle").addClass("bg-gray-600");
    u.searchParams.set("toc","true");
    if (document.getElementById('toc-content').innerHTML.trim() === '') {
      extractHeadings();
    }
  } else {
    $("#accessory-container").addClass("hidden");
    u.searchParams.delete("toc");
  }

  window.history.pushState({}, '', u);
  syncMaldevParam();
}

function toggleProgress() {
  // close others via their toggles so DOM state stays consistent
  var maldevDb  = document.getElementById("maldevDB");
  var objectives= document.getElementById("objectives");
  var toc       = document.getElementById("toc-container");
  if (!maldevDb.classList.contains("hidden"))   toggleIde();
  if (!objectives.classList.contains("hidden")) toggleObjectives();
  if (!toc.classList.contains("hidden"))        toggleToC();

  var progressContainer = document.getElementById("progress-container");
  let u = new URL(window.location.href);
  ['toc','maldevdb','objectives'].forEach(k => u.searchParams.delete(k));

  if (progressContainer.classList.contains("hidden")) {
    $("#progress-container").removeClass("hidden");
    $("#progressToggle").addClass("bg-gray-600");
    u.searchParams.set("progress","true");
  } else {
    $("#progress-container").addClass("hidden");
    $("#progressToggle").removeClass("bg-gray-600");
    u.searchParams.delete("progress");
  }

  window.history.pushState({}, '', u);
  syncMaldevParam();
}


function toggleScreenWidth(){
  var navbar=document.getElementById("navbar");
  if(navbar.classList.contains("hidden")){
    $("#navbar,#footer").removeClass("hidden");
    $("#height-container").removeClass("h-full").addClass("max-h-[800px]");
    $("#description-container").addClass("overflow-auto");
    $("#enlargeToggle").addClass("bg-gray-600");
  }else{
    $("#navbar,#footer").addClass("hidden");
    $("#height-container").removeClass("max-h-[800px]").addClass("h-full");
    $("#description-container").removeClass("overflow-auto");
    $("#enlargeToggle").removeClass("bg-gray-600");
  }
}


function extractHeadings() {
  const headings   = document.querySelectorAll('h1, h2, h3, h4, h5, h6');
  const tocContent = document.getElementById('toc-content');

  if (!tocContent) return;

  let html = '';
  headings.forEach((heading, index) => {
    if (!heading.id) heading.id = 'toc-heading-' + index;

    const level  = parseInt(heading.tagName.charAt(1), 10);
    const title  = heading.textContent.trim();
    const indent = 20 + (level - 1) * 20; // 20px per level

    html += `
      <div class="py-2 px-2 hover:bg-gray-600 cursor-pointer transition-colors"
           style="padding-left:${indent}px"
           data-target-id="${heading.id}">
        <span class="text-gray-300 hover:text-white text-sm">${title}</span>
      </div>`;
  });

  tocContent.innerHTML = html;

  // Remove skeleton once content is ready
  const skel = document.getElementById('toc-skeleton');
  if (skel) skel.remove();

  // Smooth scroll bindings
  tocContent.querySelectorAll('[data-target-id]').forEach(item => {
    item.addEventListener('click', () => {
      const target = document.getElementById(item.dataset.targetId);
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });
}