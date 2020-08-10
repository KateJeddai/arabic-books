// send a request to upload a book
const bookForm = document.getElementById('form-book');
bookForm.addEventListener('submit', (e) => {
    addFormData();
})

const addFormData = () => {
  const bookInput = document.getElementById('book-input');
  const bookTypeSelect = document.getElementById('book-type');
  const bookType = bookTypeSelect[bookTypeSelect.selectedIndex].value;

  const formData = new FormData();   
  formData.append('book', bookInput.files[0]);  
  formData.append('booksPicker', bookType);

  fetch('/books/upload-book', {
    method: 'POST', 
    headers: {
      'Content-Type': 'multipart/form-data'
    },    
    body: formData 
  })
    .then(response => response.json())
    .then(data => console.log(data));
}

// if signup form is empty (validation)
const signup_form = document.querySelector('.signup-form'),
      inputfields =  document.querySelectorAll('.form-control'),
      username = document.querySelector('#username'),
      usernameholder = document.querySelector('#usernameholder'),
      email = document.querySelector('#email'),
      emailholder = document.querySelector('#emailholder'),
      pass = document.querySelector('#pass'),
      enterpass = document.querySelector('#enter-pass'),
      tooltip = document.querySelector('.tooltip'),
      copypass = document.querySelector('#copy-pass'),
      confirmpass = document.querySelector('#confirm-pass'),
      dangers = document.querySelectorAll('.danger'),
      btn_signup = document.querySelector('.btn-signup');
      
copypass.addEventListener('keyup', () => {    
  if(signup_form.elements["password"].value.trim().length > 0 && signup_form.elements["copypassword"].value.trim().length > 0 &&
     signup_form.elements["password"].value !== signup_form.elements["copypassword"].value){
     confirmpass.innerText = "Passwords don't match";
     confirmpass.style.color = "#f94646";
  }
  else if(signup_form.elements["password"].value.trim().length > 0 && signup_form.elements["copypassword"].value.trim().length > 0 && 
          signup_form.elements["password"].value === signup_form.elements["copypassword"].value){
     confirmpass.innerText = "Passwords match";
     confirmpass.style.color = "#6B7B4C";
  }
  else {
    confirmpass.innerText = "";
  }
})

pass.addEventListener('keyup', () => {    
  if(signup_form.elements["copypassword"].value.trim().length > 0 && signup_form.elements["password"].value.trim().length > 0 &&
     signup_form.elements["password"].value !== signup_form.elements["copypassword"].value){        
     confirmpass.innerText = "Passwords don't match";
     confirmpass.style.color = "#f94646";
  }
  else if(signup_form.elements["password"].value.trim().length > 0 && signup_form.elements["copypassword"].value.trim().length > 0 && 
          signup_form.elements["password"].value === signup_form.elements["copypassword"].value){
     confirmpass.innerText = "Passwords match";
     confirmpass.style.color = "#6B7B4C";
  } 
  else {
    confirmpass.innerText = "";
  }
})

pass.addEventListener('focus', () => {
    tooltip.classList.add('tooltip_opened');
})

pass.addEventListener('blur', () => {
    tooltip.classList.remove('tooltip_opened');
})

const validateMyForm = () => {
      inputfields.forEach((inp) => {
          if(!inp.value) {
            event.preventDefault(); 
            switch(inp.name) {
              case "username": 
                  usernameholder.innerText = "Choose a username!";
                  break;
              case "email": 
                  emailholder.innerText = "Enter an email!";
                  break;
              case "password": 
                  enterpass.innerText = "Create a password!";
                  break;
              case "copypassword": 
                  confirmpass.innerText = "Confirm your password!";    
                  break;         
            }
            return false;
          }
      })
      inputfields.forEach((inp) => {
          inp.addEventListener('focus', (e) => {
              dangers.forEach(dan => dan.innerText = '');
              confirmpass.style.color = "#f94646";
          })
      })
}
