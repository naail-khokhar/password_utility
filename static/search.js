/**
 * Implements client‑side search over saved password entries
 * - Gathers all vault items at page load
 * - Sorts entries alphabetically
 * - Finds prefix and substring matches
 * - Toggles visibility of matching items and their categories
 */

let allPasswordEntries = [];

/**
 * Initialize search functionality by collecting all password entries
 */
function initializeSearch() {
    // Collect initial vault entries for later lookup
    collectAllEntries();
}

/**
 * Collect all password entries from the DOM
 */
function collectAllEntries() {
    // Build an array of {element, site, parent} for each entry
    allPasswordEntries = [];
    const vaultItems = document.querySelectorAll('.vault-item');
    vaultItems.forEach(item => {
        const site = item.querySelector('.site').textContent.trim();
        allPasswordEntries.push({
            element: item,
            site: site.toLowerCase(),
            parent: item.parentElement
        });
    });
}

/**
 * Merge sort implementation for sorting entries
 * @param {Array} arr - Array of entries to sort
 * @returns {Array} - Sorted array
 */
function mergeSort(arr) {
    // Sort entries by site name using merge sort
    if (arr.length <= 1) return arr;
    
    const mid = Math.floor(arr.length / 2);
    const left = mergeSort(arr.slice(0, mid));
    const right = mergeSort(arr.slice(mid));
    
    return merge(left, right);
}

/**
 * Merge two sorted arrays
 * @param {Array} left - Left sorted array
 * @param {Array} right - Right sorted array
 * @returns {Array} - Merged sorted array
 */
function merge(left, right) {
    // Merge two sorted arrays for mergeSort
    let result = [];
    let leftIndex = 0;
    let rightIndex = 0;
    
    while (leftIndex < left.length && rightIndex < right.length) {
        if (left[leftIndex].site < right[rightIndex].site) {
            result.push(left[leftIndex]);
            leftIndex++;
        } else {
            result.push(right[rightIndex]);
            rightIndex++;
        }
    }
    
    return result.concat(left.slice(leftIndex)).concat(right.slice(rightIndex));
}

/**
 * Binary search implementation for finding entries with matching prefixes
 * @param {Array} sortedArr - Sorted array to search in
 * @param {string} prefix - Prefix to search for
 * @returns {Array} - Array of entries with matching prefix
 */
function binarySearchPrefix(sortedArr, prefix) {
    // Find all entries starting with the given prefix
    let results = [];
    let low = 0;
    let high = sortedArr.length - 1;
    let prefixLower = prefix.toLowerCase();
    
    // Binary search offers O(log n) performance for finding the first match position
    // This is much faster than linear scanning through all entries, especially with large vaults
    while (low <= high) {
        let mid = Math.floor((low + high) / 2);
        if (sortedArr[mid].site.startsWith(prefixLower)) {
            // Found a match, now collect all matches
            let i = mid;
            // Check elements to the left
            while (i >= 0 && sortedArr[i].site.startsWith(prefixLower)) {
                results.unshift(sortedArr[i]);
                i--;
            }
            
            // Check elements to the right
            i = mid + 1;
            while (i < sortedArr.length && sortedArr[i].site.startsWith(prefixLower)) {
                results.push(sortedArr[i]);
                i++;
            }
            break;
        } else if (sortedArr[mid].site < prefixLower) {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }
    
    return results;
}

/**
 * Search function combining binary search for prefixes and additional filtering for substrings
 */
function performSearch() {
    // Show/hide entries based on input value
    const query = document.getElementById('search-input').value.trim();
    
    // Show search icon if search is cleared
    if (query === '') {
        const searchIcon = document.getElementById('search-icon');
        const searchBox = document.getElementById('search-box');
        // Only toggle if visible and button is pressed (not on initial load)
        if (searchBox.style.display !== 'none' && document.activeElement !== document.getElementById('search-input')) {
            searchBox.style.display = 'none';
            searchIcon.style.display = 'flex';
        }
    }
    
    // Reset all category visibility
    document.querySelectorAll('.category-content').forEach(content => {
        content.classList.remove('collapsed');
    });
    
    document.querySelectorAll('.category-header').forEach(header => {
        header.classList.remove('collapsed');
    });
    
    if (query === '') {
        // Show all entries if query is empty
        document.querySelectorAll('.vault-item').forEach(item => {
            item.style.display = '';
        });
        return;
    }
    
    // Perform merge sort to order entries by site name
    const sortedEntries = mergeSort([...allPasswordEntries]);
    
    // Use binary search to find entries with matching prefixes
    const prefixMatches = binarySearchPrefix(sortedEntries, query);
    
    // Find entries that contain the query but don't start with it
    // Two-phase search approach: prefix matches first (faster binary search), then substring matches (linear scan)
    // This prioritizes prefix matches while still finding other relevant results
    const containsQuery = sortedEntries.filter(entry => 
        !entry.site.startsWith(query.toLowerCase()) && 
        entry.site.includes(query.toLowerCase())
    );
    
    // Combine results
    const allMatches = [...prefixMatches, ...containsQuery];
    
    // Hide all entries first
    document.querySelectorAll('.vault-item').forEach(item => {
        item.style.display = 'none';
    });
    
    // Show matching entries
    allMatches.forEach(entry => {
        entry.element.style.display = '';
        
        // Make sure the parent category is visible
        if (entry.parent) {
            entry.parent.classList.remove('collapsed');
            const header = entry.parent.previousElementSibling;
            if (header && header.classList.contains('category-header')) {
                header.classList.remove('collapsed');
            }
        }
    });
    
    // Hide empty categories
    // This collapses categories with no matches to reduce visual clutter while searching
    document.querySelectorAll('.category-content').forEach(category => {
        const visibleItems = Array.from(category.querySelectorAll('.vault-item')).filter(
            item => item.style.display !== 'none'
        );
        if (visibleItems.length === 0) {
            category.classList.add('collapsed');
            const header = category.previousElementSibling;
            if (header && header.classList.contains('category-header')) {
                header.classList.add('collapsed');
            }
        }
    });
}

/**
 * Show the search box and hide the search icon
 * @param {HTMLElement} searchIcon - Search icon element
 */
function showSearchBox(searchIcon) {
    // Reveal the search input and focus it
    const searchBox = document.getElementById('search-box');
    const searchInput = document.getElementById('search-input');
    
    if (searchBox.style.display === 'none') {
        searchBox.style.display = 'flex';
        searchInput.focus();
        searchIcon.style.display = 'none';
    }
}

/**
 * Handle clicking outside the search box
 * @param {Event} e - Click event
 */
function handleClickOutsideSearch(e) {
    // Hide search box when clicking outside, if empty
    // Clean UI pattern keeps the interface tidy - only show search when actively being used
    const searchIcon = document.getElementById('search-icon');
    const searchBox = document.getElementById('search-box');
    const searchInput = document.getElementById('search-input');
    
    if (!searchBox.contains(e.target) && e.target !== searchIcon && searchBox.style.display !== 'none') {
        if (searchInput.value === '') {
            searchBox.style.display = 'none';
            searchIcon.style.display = 'flex';
        }
    }
}

/**
 * Handle escape key press to close search box
 * @param {Event} e - Keydown event
 */
function handleSearchEscape(e) {
    // Close search on Escape key and reset input
    if (e.key === 'Escape') {
        const searchBox = document.getElementById('search-box');
        const searchIcon = document.getElementById('search-icon');
        
        if (searchBox.style.display !== 'none') {
            searchBox.style.display = 'none';
            searchIcon.style.display = 'flex';
            document.getElementById('search-input').value = '';
            performSearch(); // Reset search results
        }
    }
}
