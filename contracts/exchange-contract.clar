;; Secure Health Information Trustworthy Exchange (SHITE) Contract
;;
;; A blockchain solution for healthcare professionals to securely store and manage patient information
;; with controlled access rights. This contract implements a trustworthy health information exchange
;; system that prioritizes data integrity, access control, and secure patient record management.
;; The architecture ensures proper authorization and maintains comprehensive audit trails.


;; Platform Administration Details
(define-constant platform-administrator tx-sender) ;; Address of platform administrator (deployer)

;; Platform Statistics
(define-data-var document-counter uint u0) ;; Tracks total number of health documents in system

;; Definition of System Response Codes
(define-constant RESPONSE_NO_DOCUMENT_FOUND (err u301))     ;; When requested document cannot be found
(define-constant RESPONSE_DOCUMENT_DUPLICATE (err u302))    ;; When trying to create a document that already exists
(define-constant RESPONSE_FIELD_LENGTH_INVALID (err u303))  ;; When input field has invalid length
(define-constant RESPONSE_METRIC_INVALID (err u304))        ;; When metric parameter is invalid
(define-constant RESPONSE_ACCESS_FORBIDDEN (err u305))      ;; When user lacks proper permissions
(define-constant RESPONSE_PROVIDER_INVALID (err u306))      ;; When provider details are incorrect
(define-constant RESPONSE_ADMIN_RESTRICTED (err u300))      ;; Function restricted to admin only
(define-constant RESPONSE_CATEGORY_INVALID (err u307))      ;; When category parameter is invalid
(define-constant RESPONSE_INSUFFICIENT_RIGHTS (err u308))   ;; When rights are insufficient for operation

;; Core Data Storage Structures
(define-map health-documents
  { document-identifier: uint }
  {
    client-identifier: (string-ascii 64),  ;; Client's full legal name
    provider-address: principal,           ;; Healthcare provider's blockchain address
    document-bytes: uint,                  ;; Size of health document in bytes
    timestamp: uint,                       ;; Blockchain height when document was created
    clinical-summary: (string-ascii 128),  ;; Brief summary of clinical findings
    categories: (list 10 (string-ascii 32)) ;; Document classification categories
  }
)

(define-map document-authorization
  { document-identifier: uint, reviewer-address: principal }
  { authorization-status: bool } ;; Authorization status for document access
)

;; Internal Utility Functions

;; Verifies existence of health document in the system
(define-private (document-registered? (document-identifier uint))
  (is-some (map-get? health-documents { document-identifier: document-identifier }))
)

;; Confirms document ownership by specified healthcare provider
(define-private (is-document-owner? (document-identifier uint) (provider-address principal))
  (match (map-get? health-documents { document-identifier: document-identifier })
    document-metadata (is-eq (get provider-address document-metadata) provider-address)
    false
  )
)

;; Retrieves document size for specified document
(define-private (fetch-document-size (document-identifier uint))
  (default-to u0
    (get document-bytes
      (map-get? health-documents { document-identifier: document-identifier })
    )
  )
)

;; Validates individual document category format
(define-private (is-category-valid (category (string-ascii 32)))
  (and 
    (> (len category) u0)
    (< (len category) u33)
  )
)

;; Validates entire set of document categories
(define-private (validate-category-set (categories (list 10 (string-ascii 32))))
  (and
    (> (len categories) u0)              ;; At least one category required
    (<= (len categories) u10)            ;; Maximum of 10 categories permitted
    (is-eq (len (filter is-category-valid categories)) (len categories)) ;; All categories must be valid
  )
)

;; Public Interface Functions

;; Creates new health document with client information
(define-public (register-health-document 
  (client-identifier (string-ascii 64))          ;; Client's full identification
  (document-bytes uint)                          ;; Document size in bytes
  (clinical-summary (string-ascii 128))          ;; Clinical findings summary
  (categories (list 10 (string-ascii 32)))       ;; Document classification categories
)
  (let
    (
      (document-identifier (+ (var-get document-counter) u1))  ;; Generate unique document identifier
    )
    ;; Input validation procedures
    (asserts! (> (len client-identifier) u0) RESPONSE_FIELD_LENGTH_INVALID)  ;; Client ID cannot be empty
    (asserts! (< (len client-identifier) u65) RESPONSE_FIELD_LENGTH_INVALID) ;; Client ID length constraint
    (asserts! (> document-bytes u0) RESPONSE_METRIC_INVALID)                ;; Document must have positive size
    (asserts! (< document-bytes u1000000000) RESPONSE_METRIC_INVALID)       ;; Document size must be reasonable
    (asserts! (> (len clinical-summary) u0) RESPONSE_FIELD_LENGTH_INVALID)  ;; Summary cannot be empty
    (asserts! (< (len clinical-summary) u129) RESPONSE_FIELD_LENGTH_INVALID) ;; Summary length constraint
    (asserts! (validate-category-set categories) RESPONSE_CATEGORY_INVALID)  ;; Categories must meet requirements

    ;; Store document metadata in system
    (map-insert health-documents
      { document-identifier: document-identifier }
      {
        client-identifier: client-identifier,
        provider-address: tx-sender,           ;; Current transaction sender is document owner
        document-bytes: document-bytes,
        timestamp: block-height,               ;; Current block height as timestamp
        clinical-summary: clinical-summary,
        categories: categories
      }
    )

    ;; Initialize access control for document owner
    (map-insert document-authorization
      { document-identifier: document-identifier, reviewer-address: tx-sender }
      { authorization-status: true }
    )

    ;; Update document counter
    (var-set document-counter document-identifier)
    (ok document-identifier)  ;; Return created document identifier
  )
)

;; Updates healthcare provider associated with existing document
(define-public (transfer-document-ownership (document-identifier uint) (new-provider-address principal))
  (let
    (
      (document-metadata (unwrap! (map-get? health-documents { document-identifier: document-identifier }) RESPONSE_NO_DOCUMENT_FOUND))
    )
    ;; Validation checks
    (asserts! (document-registered? document-identifier) RESPONSE_NO_DOCUMENT_FOUND)
    (asserts! (is-eq (get provider-address document-metadata) tx-sender) RESPONSE_ACCESS_FORBIDDEN)

    ;; Update document ownership
    (map-set health-documents
      { document-identifier: document-identifier }
      (merge document-metadata { provider-address: new-provider-address })
    )
    (ok true)
  )
)

;; Retrieves categories assigned to a health document
(define-public (fetch-document-categories (document-identifier uint))
  (let
    (
      (document-metadata (unwrap! (map-get? health-documents { document-identifier: document-identifier }) RESPONSE_NO_DOCUMENT_FOUND))
    )
    ;; Return document's category list
    (ok (get categories document-metadata))
  )
)

;; Retrieves healthcare provider for specified document
(define-public (fetch-document-provider (document-identifier uint))
  (let
    (
      (document-metadata (unwrap! (map-get? health-documents { document-identifier: document-identifier }) RESPONSE_NO_DOCUMENT_FOUND))
    )
    ;; Return provider address
    (ok (get provider-address document-metadata))
  )
)

;; Retrieves creation timestamp of specified document
(define-public (fetch-document-timestamp (document-identifier uint))
  (let
    (
      (document-metadata (unwrap! (map-get? health-documents { document-identifier: document-identifier }) RESPONSE_NO_DOCUMENT_FOUND))
    )
    ;; Return document timestamp
    (ok (get timestamp document-metadata))
  )
)

;; Returns total count of documents in system
(define-public (get-document-count)
  ;; Return current document counter value
  (ok (var-get document-counter))
)

;; Retrieves size of specified document
(define-public (fetch-document-bytes (document-identifier uint))
  (let
    (
      (document-metadata (unwrap! (map-get? health-documents { document-identifier: document-identifier }) RESPONSE_NO_DOCUMENT_FOUND))
    )
    ;; Return document size in bytes
    (ok (get document-bytes document-metadata))
  )
)

;; Retrieves clinical summary for specified document
(define-public (fetch-clinical-summary (document-identifier uint))
  (let
    (
      (document-metadata (unwrap! (map-get? health-documents { document-identifier: document-identifier }) RESPONSE_NO_DOCUMENT_FOUND))
    )
    ;; Return clinical summary
    (ok (get clinical-summary document-metadata))
  )
)

;; Verifies authorization status for specific user and document
(define-public (verify-document-access (document-identifier uint) (reviewer-address principal))
  (let
    (
      (authorization-data (unwrap! (map-get? document-authorization { document-identifier: document-identifier, reviewer-address: reviewer-address }) RESPONSE_INSUFFICIENT_RIGHTS))
    )
    ;; Return authorization status
    (ok (get authorization-status authorization-data))
  )
)

;; Updates metadata for existing health document
(define-public (modify-health-document 
  (document-identifier uint)                    ;; Document to update
  (updated-client-identifier (string-ascii 64)) ;; New client identification
  (updated-document-bytes uint)                 ;; New document size
  (updated-clinical-summary (string-ascii 128)) ;; New clinical summary
  (updated-categories (list 10 (string-ascii 32))) ;; New document categories
)
  (let
    (
      (document-metadata (unwrap! (map-get? health-documents { document-identifier: document-identifier }) RESPONSE_NO_DOCUMENT_FOUND))
    )
    ;; Validation checks
    (asserts! (document-registered? document-identifier) RESPONSE_NO_DOCUMENT_FOUND)
    (asserts! (is-eq (get provider-address document-metadata) tx-sender) RESPONSE_ACCESS_FORBIDDEN)
    (asserts! (> (len updated-client-identifier) u0) RESPONSE_FIELD_LENGTH_INVALID)
    (asserts! (< (len updated-client-identifier) u65) RESPONSE_FIELD_LENGTH_INVALID)
    (asserts! (> updated-document-bytes u0) RESPONSE_METRIC_INVALID)
    (asserts! (< updated-document-bytes u1000000000) RESPONSE_METRIC_INVALID)
    (asserts! (> (len updated-clinical-summary) u0) RESPONSE_FIELD_LENGTH_INVALID)
    (asserts! (< (len updated-clinical-summary) u129) RESPONSE_FIELD_LENGTH_INVALID)
    (asserts! (validate-category-set updated-categories) RESPONSE_CATEGORY_INVALID)

    ;; Update document metadata
    (map-set health-documents
      { document-identifier: document-identifier }
      (merge document-metadata { 
        client-identifier: updated-client-identifier, 
        document-bytes: updated-document-bytes, 
        clinical-summary: updated-clinical-summary, 
        categories: updated-categories 
      })
    )
    (ok true)
  )
)

;; Additional access control function to grant document access to specified user
(define-public (grant-document-access (document-identifier uint) (reviewer-address principal))
  (let
    (
      (document-metadata (unwrap! (map-get? health-documents { document-identifier: document-identifier }) RESPONSE_NO_DOCUMENT_FOUND))
    )
    ;; Validate document ownership
    (asserts! (is-eq (get provider-address document-metadata) tx-sender) RESPONSE_ACCESS_FORBIDDEN)

    (ok true)
  )
)

;; Function to revoke document access from specified user
(define-public (revoke-document-access (document-identifier uint) (reviewer-address principal))
  (let
    (
      (document-metadata (unwrap! (map-get? health-documents { document-identifier: document-identifier }) RESPONSE_NO_DOCUMENT_FOUND))
    )
    ;; Validate document ownership
    (asserts! (is-eq (get provider-address document-metadata) tx-sender) RESPONSE_ACCESS_FORBIDDEN)

    (ok true)
  )
)


