// sidebar menu on medium and smaller screens
const bars_navbars = document.querySelectorAll('.md-navbar');
      bars_navbars.forEach((bar) => {
      	 bar.addEventListener('click', () => {
      	  const sidebar = document.querySelector('.sidebar'),
      	        body_wrapper = document.querySelector('.body-wrapper'),
      	        bar_sidebar = document.querySelector('.sidebar-md-navbar');

                bar_sidebar.classList.contains('bar-opened') ? bar_sidebar.classList.remove('bar-opened') :
                                                               bar_sidebar.classList.add('bar-opened');  

                body_wrapper.classList.contains('darkened') ? body_wrapper.classList.remove('darkened') :
                                                              body_wrapper.classList.add('darkened');

      	      if(sidebar.classList.contains('visible')) {
      	      	sidebar.classList.remove('visible');
      	      	sidebar.classList.add('invisible');
      	      } else {
      	      	sidebar.classList.add('visible');
      	      	sidebar.classList.remove('invisible');
      	      }                                      
         })
      })   
 