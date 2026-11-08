const fileInput = document.getElementById('capture');
const fileName = document.getElementById('file-name');
fileInput.addEventListener('change', () => {
  fileName.textContent = fileInput.files.length ? fileInput.files[0].name : 'No file selected';
});