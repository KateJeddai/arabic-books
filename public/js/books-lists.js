// send a request to delete a book
const defineBookType = (btnClass) => {
    if(btnClass.includes('tutorials')) {
        return 'tutorials';
    } else if(btnClass.includes('dialects')) {
        return 'dialects';
    } else if(btnClass.includes('dictionaries')) {
        return 'dictionaries'
    } else {
        return;
    }
}

const deleteButtons = document.querySelectorAll('.btn-delete');
deleteButtons.forEach(btn => {
  btn.addEventListener('click', (e) => {
      const id = e.target.id;
      const booktype = defineBookType(e.target.classList.value);
      fetch(`/books/delete/${booktype}/${id}`, {
          method: 'DELETE'
      })
      .then(res => {        
          if(res.status === 200) {              
              location.reload()
          }
      })
  })
})
