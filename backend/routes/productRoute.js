const express = require("express");
const { getAllProducts, createProduct, updateProduct, deleteProduct, getProductDetails, getAdminProducts } = require("../controller/productController");
const { isAuthenticatedUser,authorizeRoles } = require("../middleware/auth");

const router = express.Router();
router.route('/products').get( getAllProducts);
router.route('/products/new').post(isAuthenticatedUser,authorizeRoles("admin"),createProduct);
router.route('/products/admin').get(getAdminProducts)
router.route('/products/:id').put(authorizeRoles("admin"),updateProduct).delete(authorizeRoles("admin"),deleteProduct).get(getProductDetails);


module.exports=router;