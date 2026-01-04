$("#navbar-phone-btn").click(function() {
    $("#navbar-default").slideToggle(500); // 500 milliseconds animation
  });

// Get references to the dropdown elements
// var aboutDropdown = document.getElementById('aboutDropDown');
var profileDropdown = document.getElementById('profileDropdown');
// var examDropdown = document.getElementById('examDropdown');

// Function to close both dropdowns
function closeDropdowns() {
  // aboutDropdown.classList.add('hidden');
  profileDropdown.classList.add('hidden');
  // examDropdown.classList.add('hidden');
}

// Function to toggle the About dropdown
function toggleAboutDropdown() {
  // aboutDropdown.classList.toggle('hidden');
  profileDropdown.classList.add('hidden');
  // examDropdown.classList.add('hidden');
}

// Function to toggle the Profile dropdown
function toggleProfileDropdown() {
  profileDropdown.classList.toggle('hidden');
  // aboutDropdown.classList.add('hidden');
  // examDropdown.classList.add('hidden');
}


// Add a click event listener to the document body
document.body.addEventListener('click', function (event) {
  // Check if the click occurred inside either dropdown or their respective buttons
  if (
    event.target !== profileDropdown &&
    event.target !== document.getElementById('aboutNavBar') &&
    event.target !== document.getElementById('profileNavBar') // &&
    // event.target !== document.getElementById('examNavBar')  // Add this line
  ) {
    // If the click occurred outside of both dropdowns and their buttons, close both dropdowns
    closeDropdowns();
  }
});