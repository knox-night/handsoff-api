const repositoryPattern = /^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?\/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?$/;
const refPattern = /^[A-Za-z0-9._/-]{1,200}$/;

function isValidGitHubSource(source) {
  return source &&
    source.type === 'github' &&
    typeof source.repository === 'string' &&
    repositoryPattern.test(source.repository) &&
    typeof source.ref === 'string' &&
    refPattern.test(source.ref) &&
    !source.ref.includes('..');
}

module.exports = { isValidGitHubSource };
