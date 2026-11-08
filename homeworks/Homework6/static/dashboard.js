const fileInput = document.getElementById('capture');
const fileName = document.getElementById('file-name');
const uploadForm = document.querySelector('.upload-form');
const uploadError = document.getElementById('upload-error');
const maxRequestSize = Number(uploadForm.dataset.maxRequestSize);

function validateFileSize() {
  const file = fileInput.files[0];
  const tooLarge = file && file.size >= maxRequestSize;
  uploadError.textContent = tooLarge ? 'The file is too large. Upload a capture smaller than 64 MiB.' : '';
  uploadError.hidden = !tooLarge;
  return !tooLarge;
}

fileInput.addEventListener('change', () => {
  fileName.textContent = fileInput.files.length ? fileInput.files[0].name : 'No file selected';
  validateFileSize();
});

uploadForm.addEventListener('submit', event => {
  if (!validateFileSize()) {
    event.preventDefault();
  }
});